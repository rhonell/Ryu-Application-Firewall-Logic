from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp
import datetime
import time

class FirewallVM1(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # Use OpenFlow 1.3 protocol

    def __init__(self, *args, **kwargs):
        super(FirewallVM1, self).__init__(*args, **kwargs)
        self.logger.info("🔐 VM1 Firewall Initialized")
        self.mac_to_port = {}  # Track which MAC address is on which switch port
        self.log_file = "/home/ryu/firewall_logsvm1.txt"  # Log file path
        self.protected_ip = "10.0.0.2"  # The IP we're protecting
        self.blocked_ports = [21, 22, 23, 25, 135, 139, 445, 5040, 7680,  # Dangerous ports to block
                              49664, 49665, 49666, 49667, 49668, 51173, 51174, 51175]
        self.connection_table = {}  # Track active TCP connections
        self.connection_timeout = 300  # 5-minute connection timeout

    def log_event(self, message):
        # Log messages to both console and file
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_message = f"{timestamp} {message}"
        self.logger.info(log_message)
        with open(self.log_file, "a") as f:
            f.write(log_message + "\n")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        # Helper function to install flow rules on switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     priority=priority, match=match,
                                     instructions=inst, idle_timeout=idle_timeout,
                                     hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                     instructions=inst, idle_timeout=idle_timeout,
                                     hard_timeout=hard_timeout)
        datapath.send_msg(mod)  # Send rule to switch

    def _update_connection_state(self, flow_key, new_state):
        # Update TCP connection state in tracking table
        self.connection_table[flow_key] = {'state': new_state, 'timestamp': time.time()}
        self.log_event(f"🔁 State Update: {flow_key} -> {new_state}")

    def _check_tcp_state(self, flow_key, tcp_pkt):
        # Validate TCP packet follows proper state sequence
        is_syn = (tcp_pkt.bits & tcp.TCP_SYN) != 0
        is_ack = (tcp_pkt.bits & tcp.TCP_ACK) != 0
        is_rst = (tcp_pkt.bits & tcp.TCP_RST) != 0
        
        # New connection must start with SYN
        if flow_key not in self.connection_table:
            if is_syn and not is_ack:
                return 'VALID_SYN'
            else:
                self.log_event(f"⛔ Invalid TCP: Non-SYN packet for new flow {flow_key}. Flags: {self._get_tcp_flags(tcp_pkt)}")
                return 'INVALID_NO_SYN'
        
        # Existing connection state validation
        current_state = self.connection_table[flow_key]['state']
        current_flags = self._get_tcp_flags(tcp_pkt)
        
        if current_state == 'SYN_RECV':
            # Expect SYN-ACK after SYN
            if is_syn and is_ack:
                return 'VALID_SYN_ACK'
            elif is_rst:
                return 'VALID_RST'
            else:
                self.log_event(f"⛔ Invalid TCP: Expected SYN-ACK in state SYN_RECV, got {current_flags} for {flow_key}")
                return 'INVALID'
        elif current_state == 'ESTABLISHED':
            # Established connection allows data exchange
            if is_ack or (tcp_pkt.bits & tcp.TCP_PSH) or (tcp_pkt.bits & tcp.TCP_FIN) or is_rst:
                return 'VALID'
            else:
                self.log_event(f"⛔ Invalid TCP: Unexpected flags {current_flags} in ESTABLISHED state for {flow_key}")
                return 'INVALID'
        return 'VALID'

    def _cleanup_old_connections(self):
        # Remove stale connections from tracking table
        current_time = time.time()
        keys_to_delete = []
        for flow_key, data in self.connection_table.items():
            if current_time - data['timestamp'] > self.connection_timeout:
                keys_to_delete.append(flow_key)
        for key in keys_to_delete:
            self.log_event(f"🧹 Cleaning up stale connection: {key}")
            del self.connection_table[key]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Called when switch connects - install basic rules
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Table-miss rule: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.log_event("📜 Table-miss flow installed.")
        
        # Install silent drop rules for blocked ports
        for port in self.blocked_ports:
            match_to = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=self.protected_ip, tcp_dst=port)
            match_from = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=self.protected_ip, tcp_src=port)
            self.add_flow(datapath, 40, match_to, [])  # Empty actions = drop
            self.add_flow(datapath, 40, match_from, [])
            self.log_event(f"🚫 Silent drop rule installed for TCP port {port} on {self.protected_ip}")
        
        # Stateful inspection rules for TCP traffic
        match_tcp_to = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_dst=self.protected_ip)
        match_tcp_from = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=self.protected_ip)
        actions_to_controller = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 30, match_tcp_to, actions_to_controller, idle_timeout=10)
        self.add_flow(datapath, 30, match_tcp_from, actions_to_controller, idle_timeout=10)
        self.log_event("🔍 Stateful inspection rule installed for TCP packets.")
        
        # Allow ICMP traffic (ping)
        match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1, ipv4_dst=self.protected_ip)
        actions_normal = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]  # Normal processing
        self.add_flow(datapath, 10, match_icmp, actions_normal)
        self.log_event(f"✅ ICMP allowed for {self.protected_ip}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Main packet processing function
        if len(self.connection_table) > 100:
            self._cleanup_old_connections()  # Cleanup if too many connections
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        # Parse packet layers
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return
        
        # Extract packet information
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        src_mac = eth.src
        dst_mac = eth.dst
        arp_pkt = pkt.get_protocol(arp.arp)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        # Get source and destination IP addresses
        src_ip = ip.src if ip else (arp_pkt.src_ip if arp_pkt else "L2:" + src_mac)
        dst_ip = ip.dst if ip else (arp_pkt.dst_ip if arp_pkt else "L2:" + dst_mac)

        # Only process packets related to protected IP
        if ip and ip.dst != self.protected_ip and ip.src != self.protected_ip:
            return

        self.log_event(f"📦 IN: {src_ip} -> {dst_ip}")
        
        # Check for blocked TCP ports
        if ip and tcp_pkt:
            if tcp_pkt.dst_port in self.blocked_ports or tcp_pkt.src_port in self.blocked_ports:
                self.log_event(f"🚨 BLOCKED TCP ATTEMPT: {src_ip}:{tcp_pkt.src_port} -> {dst_ip}:{tcp_pkt.dst_port}")
                return  # Drop packet
        
        # Stateful TCP inspection
        if ip and tcp_pkt:
            flow_key = (src_ip, tcp_pkt.src_port, dst_ip, tcp_pkt.dst_port)
            validation_result = self._check_tcp_state(flow_key, tcp_pkt)
            
            # Drop invalid TCP packets
            if validation_result.startswith('INVALID'):
                self.log_event(f"🚨 Stateful Inspection: Dropping invalid TCP packet from {flow_key}")
                return
            
            # Update connection state based on TCP flags
            if validation_result == 'VALID_SYN':
                self._update_connection_state(flow_key, 'SYN_RECV')
            elif validation_result == 'VALID_SYN_ACK':
                self._update_connection_state(flow_key, 'ESTABLISHED')
            elif (tcp_pkt.bits & tcp.TCP_FIN) or (tcp_pkt.bits & tcp.TCP_RST):
                # Remove closed connections
                if flow_key in self.connection_table:
                    self.log_event(f"🔚 Connection closed: {flow_key}")
                    del self.connection_table[flow_key]
            else:
                # Update timestamp for active connections
                if flow_key in self.connection_table:
                    self.connection_table[flow_key]['timestamp'] = time.time()
        
        # Learn MAC addresses and forward packet
        self.mac_to_port[dpid][src_mac] = in_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]  # Known destination
        else:
            out_port = ofproto.OFPP_FLOOD  # Flood if unknown
        
        # Install flow rule for future packets in this conversation
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions, idle_timeout=15)
        
        # Forward the current packet
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFPP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _get_tcp_flags(self, tcp_pkt):
        # Convert TCP flags to readable string
        flags = []
        if tcp_pkt.bits & tcp.TCP_SYN: flags.append('SYN')
        if tcp_pkt.bits & tcp.TCP_ACK: flags.append('ACK')
        if tcp_pkt.bits & tcp.TCP_FIN: flags.append('FIN')
        if tcp_pkt.bits & tcp.TCP_RST: flags.append('RST')
        if tcp_pkt.bits & tcp.TCP_PSH: flags.append('PSH')
        if tcp_pkt.bits & tcp.TCP_URG: flags.append('URG')
        return '/'.join(flags) if flags else 'None'
