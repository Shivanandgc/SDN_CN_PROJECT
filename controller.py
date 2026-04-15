#!/usr/bin/env python3
"""
Link Failure Detection and Recovery - Ryu SDN Controller
Student: SHIVANAND | Roll: PES2UG24CS473 | Experiment: 36

Primary path : h1 -> s1 -> s2 -> h2
Backup path  : h1 -> s1 -> s3 -> s2 -> h2

FIX NOTES:
  - EventLinkDelete is unreliable for configLinkStatus; use a hub poller instead.
  - OFPFC_DELETE with empty match was wiping table-miss rules; now delete by exact match.
  - using_backup flag now resets on link recovery so primary path can reinstall.
  - Recovery re-installs primary flows after link comes back up.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event as topo_event
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
import logging

logging.basicConfig(level=logging.INFO)

H1_MAC = '00:00:00:00:00:01'
H2_MAC = '00:00:00:00:00:02'
H1_IP  = '10.0.0.1'
H2_IP  = '10.0.0.2'
S1, S2, S3 = 1, 2, 3

# How often (seconds) to poll for link state changes
POLL_INTERVAL = 2


class LinkFailureController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LinkFailureController, self).__init__(*args, **kwargs)
        self.datapaths   = {}
        self.using_backup = False
        self.primary_installed = False

        # port_map[src_dpid][dst_dpid] = port_no on src to reach dst
        self.port_map  = {}
        # host_port[(dpid, 'hX')] = port number
        self.host_port = {}

        # Track known active links as frozensets {dpid_a, dpid_b}
        self.known_links = set()

        self.logger.info("")
        self.logger.info("=" * 60)
        self.logger.info("   SDN Controller Started — OpenFlow 1.3")
        self.logger.info("   Experiment 36: Link Failure Detection & Recovery")
        self.logger.info("   Student: SHIVANAND | PES2UG24CS473")
        self.logger.info("=" * 60)
        self.logger.info("")

        # Start the link-state poller
        self.monitor_thread = hub.spawn(self._link_monitor)

    # ------------------------------------------------------------------ #
    #  Polling monitor — reliable alternative to EventLinkDelete
    # ------------------------------------------------------------------ #
    def _link_monitor(self):
        """Poll topology every POLL_INTERVAL seconds to detect failures/recovery."""
        hub.sleep(5)  # give topology time to settle first
        while True:
            hub.sleep(POLL_INTERVAL)
            try:
                self._check_link_state()
            except Exception as e:
                self.logger.debug(f"[MONITOR] Error: {e}")

    def _check_link_state(self):
        links = get_link(self, None)
        current_pairs = set()
        for lnk in links:
            pair = frozenset([lnk.src.dpid, lnk.dst.dpid])
            current_pairs.add(pair)

        s1_s2 = frozenset([S1, S2])

        # --- Detect FAILURE: s1<->s2 was present, now gone ---
        if s1_s2 in self.known_links and s1_s2 not in current_pairs:
            if not self.using_backup:
                self.using_backup = True
                self.primary_installed = False
                self.logger.warning("")
                self.logger.warning("=" * 60)
                self.logger.warning("[LINK FAILURE]   ALERT! Primary link s1 <-> s2 FAILED!")
                self.logger.warning("                 Switching to BACKUP path via s3...")
                self.logger.warning("=" * 60)
                hub.spawn(self._install_backup_flows)

        # --- Detect RECOVERY: s1<->s2 is back, and we were on backup ---
        if s1_s2 not in self.known_links and s1_s2 in current_pairs:
            if self.using_backup:
                self.using_backup = False
                self.primary_installed = False
                self.logger.info("")
                self.logger.info("=" * 60)
                self.logger.info("[LINK RECOVERY]  Primary link s1 <-> s2 is BACK!")
                self.logger.info("                 Reinstalling PRIMARY path flows...")
                self.logger.info("=" * 60)
                hub.spawn_after(1, self._try_install_primary)

        self.known_links = current_pairs

    # ------------------------------------------------------------------ #
    #  Switch connects / disconnects
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == CONFIG_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info(
                f"[SWITCH CONNECTED]   Switch s{datapath.id} connected.")
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.logger.warning(
                f"[SWITCH DISCONNECTED] Switch s{datapath.id} disconnected.")

    # ------------------------------------------------------------------ #
    #  Handshake — install base rules
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Drop IPv6
        self._add_flow(datapath, 10,
                       parser.OFPMatch(eth_type=0x86DD), [])

        # Table-miss → send to controller (priority 0)
        self._add_flow(datapath, 0,
                       parser.OFPMatch(),
                       [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                               ofproto.OFPCML_NO_BUFFER)])

        self.logger.info(
            f"[FLOW INSTALLED]     Switch s{datapath.id}: Base rules installed.")

    # ------------------------------------------------------------------ #
    #  Topology events — build port map
    # ------------------------------------------------------------------ #
    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self, ev):
        link     = ev.link
        src      = link.src.dpid
        dst      = link.dst.dpid
        src_port = link.src.port_no

        if src not in self.port_map:
            self.port_map[src] = {}
        self.port_map[src][dst] = src_port

        self.logger.info(
            f"[TOPOLOGY]           Link ACTIVE: s{src}(p{src_port}) -> s{dst}")

        hub.spawn_after(2, self._try_install_primary)

    # ------------------------------------------------------------------ #
    #  Packet-in — learn host ports + flood for ARP
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == 0x86DD:
            return

        src_mac = eth.src

        # Learn which port hosts are on
        if src_mac == H1_MAC and dpid == S1:
            if self.host_port.get((S1, 'h1')) != in_port:
                self.host_port[(S1, 'h1')] = in_port
                self.logger.info(
                    f"[HOST LEARNED]       h1 ({H1_MAC}) on s1 port {in_port}")
                hub.spawn_after(1, self._try_install_primary)

        if src_mac == H2_MAC and dpid == S2:
            if self.host_port.get((S2, 'h2')) != in_port:
                self.host_port[(S2, 'h2')] = in_port
                self.logger.info(
                    f"[HOST LEARNED]       h2 ({H2_MAC}) on s2 port {in_port}")
                hub.spawn_after(1, self._try_install_primary)

        # Flood so ARP works
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ------------------------------------------------------------------ #
    #  Install PRIMARY flows
    # ------------------------------------------------------------------ #
    def _try_install_primary(self):
        if self.using_backup:
            return
        if self.primary_installed:
            return

        # Need inter-switch ports for s1<->s2
        needed = [(S1, S2), (S2, S1)]
        for (a, b) in needed:
            if a not in self.port_map or b not in self.port_map.get(a, {}):
                return  # not ready yet

        h1_port = self.host_port.get((S1, 'h1'))
        h2_port = self.host_port.get((S2, 'h2'))
        if not h1_port or not h2_port:
            return

        s1_to_s2 = self.port_map[S1][S2]
        s2_to_s1 = self.port_map[S2][S1]

        self.logger.info("")
        self.logger.info("[PRIMARY PATH]       Installing PRIMARY path flows:")
        self.logger.info(f"[PRIMARY PATH]       h1->s1(p{s1_to_s2})->s2(p{h2_port})->h2")
        self.logger.info(f"[PRIMARY PATH]       h2->s2(p{s2_to_s1})->s1(p{h1_port})->h1")
        self.logger.info("")

        if S1 in self.datapaths:
            dp = self.datapaths[S1]
            self._install_ip_and_arp(dp, H1_IP, H2_IP, H2_MAC, s1_to_s2)
            self._install_ip_and_arp(dp, H2_IP, H1_IP, H1_MAC, h1_port)
            self.logger.info(
                f"[FLOW INSTALLED]     s1: h1->h2 via p{s1_to_s2} | h2->h1 via p{h1_port}")

        if S2 in self.datapaths:
            dp = self.datapaths[S2]
            self._install_ip_and_arp(dp, H1_IP, H2_IP, H2_MAC, h2_port)
            self._install_ip_and_arp(dp, H2_IP, H1_IP, H1_MAC, s2_to_s1)
            self.logger.info(
                f"[FLOW INSTALLED]     s2: h1->h2 via p{h2_port} | h2->h1 via p{s2_to_s1}")

        self.primary_installed = True
        self.logger.info("")
        self.logger.info("[PRIMARY PATH]       All primary flows installed. Network READY!")
        self.logger.info("")

    # ------------------------------------------------------------------ #
    #  Install BACKUP flows
    # ------------------------------------------------------------------ #
    def _install_backup_flows(self):
        needed = [(S1, S3), (S3, S2), (S2, S3), (S3, S1)]
        for (a, b) in needed:
            if a not in self.port_map or b not in self.port_map.get(a, {}):
                self.logger.warning(f"[BACKUP]  Port s{a}->s{b} not known yet, retrying...")
                hub.spawn_after(1, self._install_backup_flows)
                return

        h1_port = self.host_port.get((S1, 'h1'))
        h2_port = self.host_port.get((S2, 'h2'))
        if not h1_port or not h2_port:
            hub.spawn_after(1, self._install_backup_flows)
            return

        s1_to_s3 = self.port_map[S1][S3]
        s3_to_s2 = self.port_map[S3][S2]
        s2_to_s3 = self.port_map[S2][S3]
        s3_to_s1 = self.port_map[S3][S1]

        self.logger.info("")
        self.logger.info("[BACKUP PATH]        Installing BACKUP path flows:")
        self.logger.info(f"[BACKUP PATH]        h1->s1(p{s1_to_s3})->s3(p{s3_to_s2})->s2(p{h2_port})->h2")
        self.logger.info(f"[BACKUP PATH]        h2->s2(p{s2_to_s3})->s3(p{s3_to_s1})->s1(p{h1_port})->h1")
        self.logger.info("")

        # *** FIX: Delete only priority-20 IP/ARP flows, NOT the table-miss rule ***
        # Delete per-match instead of wildcard to avoid wiping base rules
        self._delete_forwarding_flows()

        # s1: forward via s3
        if S1 in self.datapaths:
            dp = self.datapaths[S1]
            self._install_ip_and_arp(dp, H1_IP, H2_IP, H2_MAC, s1_to_s3)
            self._install_ip_and_arp(dp, H2_IP, H1_IP, H1_MAC, h1_port)
            self.logger.info(
                f"[FLOW INSTALLED]     s1: h1->h2 via p{s1_to_s3}(->s3) | h2->h1 via p{h1_port}(->h1)")

        # s3: forward between s1 and s2
        if S3 in self.datapaths:
            dp = self.datapaths[S3]
            self._install_ip_and_arp(dp, H1_IP, H2_IP, H2_MAC, s3_to_s2)
            self._install_ip_and_arp(dp, H2_IP, H1_IP, H1_MAC, s3_to_s1)
            self.logger.info(
                f"[FLOW INSTALLED]     s3: h1->h2 via p{s3_to_s2}(->s2) | h2->h1 via p{s3_to_s1}(->s1)")

        # s2: unchanged exit port toward h2, but now returns via s3
        if S2 in self.datapaths:
            dp = self.datapaths[S2]
            self._install_ip_and_arp(dp, H1_IP, H2_IP, H2_MAC, h2_port)
            self._install_ip_and_arp(dp, H2_IP, H1_IP, H1_MAC, s2_to_s3)
            self.logger.info(
                f"[FLOW INSTALLED]     s2: h1->h2 via p{h2_port}(->h2) | h2->h1 via p{s2_to_s3}(->s3)")

        self.logger.info("")
        self.logger.info("[BACKUP PATH]        Backup flows installed. Connectivity RESTORED!")
        self.logger.info("[REROUTING]          Traffic: h1->s1->s3->s2->h2")
        self.logger.info("")

    # ------------------------------------------------------------------ #
    #  Delete only priority-20 forwarding flows (IP + ARP), not base rules
    # ------------------------------------------------------------------ #
    def _delete_forwarding_flows(self):
        """Surgically delete only the priority-20 IP and ARP forwarding flows."""
        for dpid, dp in self.datapaths.items():
            ofproto = dp.ofproto
            parser  = dp.ofproto_parser

            # Delete IP flows (eth_type=0x0800) at priority 20
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                priority=20,
                match=parser.OFPMatch(eth_type=0x0800),
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY)
            dp.send_msg(mod)

            # Delete ARP flows (eth_type=0x0806) at priority 20
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                priority=20,
                match=parser.OFPMatch(eth_type=0x0806),
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY)
            dp.send_msg(mod)

    # ------------------------------------------------------------------ #
    #  Helper — install both IP and ARP flow for a direction
    # ------------------------------------------------------------------ #
    def _install_ip_and_arp(self, datapath, src_ip, dst_ip, dst_mac, out_port):
        parser = datapath.ofproto_parser
        # IP flow
        self._add_flow(datapath, 20,
                       parser.OFPMatch(eth_type=0x0800,
                                       ipv4_src=src_ip, ipv4_dst=dst_ip),
                       [parser.OFPActionOutput(out_port)])
        # ARP flow
        self._add_flow(datapath, 20,
                       parser.OFPMatch(eth_type=0x0806, eth_dst=dst_mac),
                       [parser.OFPActionOutput(out_port)])

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(
                       ofproto.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        kwargs  = dict(datapath=datapath, priority=priority,
                       match=match, instructions=inst,
                       idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))
