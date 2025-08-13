from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp
import datetime

class TargetedFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TargetedFirewall, self).__init__(*args, **kwargs)
        self.logger.info("🔐 Targeted SDN Firewall initialized")
        self.mac_to_port = {}
        self.log_file = "firewall_logs.txt"
        self.protected_ip = "10.0.0.4"  # Apply rules only for this IP

    def log_event(self, message):
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_message = f"{timestamp} {message}"
        self.logger.info(log_message)
        with open(self.log_file, "a") as f:
            f.write(log_message + "\n")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Table-miss flow (send unmatched packets to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.log_event(" Table-miss flow installed")

        # Block specific ports ONLY for the protected host
        blocked_ports = [22, 135, 139, 445, 7680, 49664, 49665, 49666, 49667, 49668, 49669, 49670]
        for port in blocked_ports:
            match1 = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                     ipv4_dst=self.protected_ip, tcp_dst=port)
            match2 = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                     ipv4_src=self.protected_ip, tcp_src=port)
            self.add_flow(datapath, 20, match1, [])
            self.add_flow(datapath, 20, match2, [])
            self.log_event(f" Blocking TCP port {port} for host {self.protected_ip}")

        # Allow ICMP for testing
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=1,
                                ipv4_dst=self.protected_ip)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 10, match, actions)
        self.log_event(f" ICMP allowed for {self.protected_ip}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if eth_pkt.ethertype == 0x88cc:  # Ignore LLDP
            return

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst
        src_ip = ip_pkt.src if ip_pkt else "N/A"
        dst_ip = ip_pkt.dst if ip_pkt else "N/A"

        self.log_event(f" Packet in: {src_ip} → {dst_ip}, in_port={in_port}")

        # ICMP detection for protected IP
        if icmp_pkt and (src_ip == self.protected_ip or dst_ip == self.protected_ip):
            self.log_event(f" ICMP from {src_ip} to {dst_ip}")

        # TCP port scan detection for protected IP
        if tcp_pkt and (src_ip == self.protected_ip or dst_ip == self.protected_ip):
            dst_port = tcp_pkt.dst_port
            if dst_port in [22, 135, 139, 445, 7680, 49664, 49665, 49666, 49667, 49668, 49669, 49670]:
                self.log_event(f" BLOCKED TCP attempt on port {dst_port} for {self.protected_ip}")
                return

        # MAC learning
        self.mac_to_port[dpid][src_mac] = in_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 5, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 5, match, actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
