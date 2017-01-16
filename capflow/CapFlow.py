"""
    This file contains the controller logic for the app that controls the captive portal authentication.
    There is a REST interface class in the same package 'rest.py'.

   based on the love child of CapFlow and ACLSwitch
   from https://github.com/ederlf/CapFlow  and https://github.com/bakkerjarr/ACLSwitch
"""



# licensing stuff

# Python
import collections
import logging

# Ryu - OpenFlow
from ryu.controller.ofp_event import EventOFPPacketIn
from ryu.controller.ofp_event import EventOFPSwitchFeatures
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.lib.packet import arp
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3

# Ryu - REST API
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset

# Us
import config
from abc_ryu_app import ABCRyuApp
from rest import UserController2


class Proto(object):
    """Class for protocol numbers
    """
    ETHER_IP = 0x800
    ETHER_ARP = 0x806
    IP_UDP = 17
    IP_TCP = 6
    TCP_HTTP = 80
    UDP_DNS = 53

class CapFlowInterface():

    def __init__(self, cf, *args, **kwargs):

        self.cf = cf
       
    def is_authed(self, ip):
        print self.cf.authenticate[ip]
        if self.cf.authenticate[ip] == {}:
            return False
        return True

    def log_client_off(self, ip, user):
        self.cf.log_client_off(ip, user)

    def new_client(self, ip, user):
        self.cf.new_client(ip, user)


class CapFlow(ABCRyuApp):
    """A simple application for learning MAC addresses and
    establishing MAC-to-switch-port mappings.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    _APP_NAME = "CapFlow"
    _EXPECTED_HANDLERS = (EventOFPPacketIn.__name__,
                          EventOFPSwitchFeatures.__name__)

    def __init__(self, contr, *args, **kwargs):
        # super(CapFlow, self).__init__(*args, **kwargs)
        self._contr = contr
        self._table_id_cf = 1
        self._supported = self._verify_contr_handlers()

        self.mac_to_port = collections.defaultdict(dict)
        self.ip_to_mac = collections.defaultdict(dict)
        self.authenticate = collections.defaultdict(dict)

        self.next_table = 2

        self.CRI = CapFlowInterface(self)	

        self._contr._wsgi.registory['UserController2'] = self.CRI
        UserController2.register(self._contr._wsgi)
        
        min_lvl = logging.DEBUG
        console_handler = logging.StreamHandler()
        console_handler.setLevel(min_lvl)
        #formatter = logging.Formatter("%(asctime)s - %(levelname)s - "
        #                              "%(name)s - %(message)s")
        formatter = logging.Formatter("%(levelname)s - %(name)s - %("
                                      "message)s")
        console_handler.setFormatter(formatter)
        logging_config = {"min_lvl": min_lvl, "propagate":
                                False, "handler": console_handler}
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])
        
        self._logging.info("Started CapFlow...");

    def log_client_off(self, ip, user):
        self._logging.info("Client on ip %s has logged off. removing rules now.", ip)
        del self.authenticate[ip]
        for datapath in self._contr.get_all():
            datapath = datapath[1]

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            mac = self.ip_to_mac[ip]
            # the authenticated l2 flows.
            # this will probably delete the rules that allow the you have been logged off page
            match = parser.OFPMatch(eth_src=mac)
            self._contr.remove_flow(datapath, parser, self._table_id_cf,
                                    ofproto.OFPFC_DELETE, 50000, 
                                    match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
            match = parser.OFPMatch(eth_dst=mac)
            self._contr.remove_flow(datapath, parser, self._table_id_cf,
                                    ofproto.OFPFC_DELETE, 50000, 
                                    match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
            # send to controller rules
            match = parser.OFPMatch(eth_src=mac)
            self._contr.remove_flow(datapath, parser, self._table_id_cf,
                                    ofproto.OFPFC_DELETE, 1000, 
                                    match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
            match = parser.OFPMatch(eth_dst=mac)
            self._contr.remove_flow(datapath, parser, self._table_id_cf,
                                    ofproto.OFPFC_DELETE, 1000, 
                                    match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

    def new_client(self, ip, user):
        self.authenticate[ip] = True
        self._logging.info("Client %s on ip %s has logged on. the rules will be installed shortly", user, ip)

    def packet_in(self, event):
        """Process a packet-in event from the controller.

        :param event: The OpenFlow event.
        """

        if event.msg.table_id != self._table_id_cf:
            self._logging.info("CapFlow not dealing with packet in messages from other tables")
            return
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        nw_dst = eth.dst
        nw_src = eth.src

        dpid = datapath.id

        self._contr.logger.info("packet type %s at switch %s from %s to %s (port %s)",
                                eth.ethertype, dpid, nw_src, nw_dst, in_port)
        if nw_src not in self.mac_to_port[dpid]:
            self._logging.info("New client: dpid %d, nw_src %s, port %d", dpid, nw_src, in_port)
            self.mac_to_port[dpid][nw_src] = in_port
            # Be sure to not forward ARP traffic so we can learn
            # sources
            self._contr.add_flow(datapath,
                                 1000,
                                 parser.OFPMatch(
                                     eth_dst=nw_src,
                                     eth_type=Proto.ETHER_ARP),
                                 [parser.OFPInstructionActions(
                                     ofproto.OFPIT_APPLY_ACTIONS,
                                     [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),]
                                     )
                                 ],
                                 0,
                                 self._table_id_cf,
                                 msg=msg,
                                 in_port=in_port
                                )
                     
        if self.deal_with_arp(datapath, msg, pkt, eth, in_port, nw_dst, nw_src):
            return

        if self.deal_with_dhcp(datapath, msg, pkt, eth, in_port, nw_dst):
            return

        # Non-ARP traffic to unknown L2 destination is dropped
        if nw_dst not in self.mac_to_port[dpid]:
            # self._contr.logger.info("      Unknown destination!")
            return

        # We know L2 destination
        out_port = self.mac_to_port[dpid][nw_dst]

        def install_dns_fwd(nw_src, nw_dst, out_port, src_port):
            """Adds flows that allow DNS requests to be made to the gateway.
            """
            self._logging.info("adding dns flows")
            # this should just be for before we authenticate.
            # (once authed all traffic allowed at L2).
            # so have relatively short timeout on rule
            # dns response packet
            self._contr.add_flow(datapath,
                                 2001,
                                 parser.OFPMatch(
                                     eth_dst=nw_src,
                                     eth_type=Proto.ETHER_IP,
                                     ip_proto=Proto.IP_UDP,
                                     udp_dst=src_port,
                                     udp_src=Proto.UDP_DNS
                                     ),
                                 [parser.OFPInstructionActions(
                                     ofproto.OFPIT_APPLY_ACTIONS,
                                     [parser.OFPActionOutput(in_port)])],
                                 0,
                                 self._table_id_cf,
                                  in_port=out_port, idle_timeout=30, packet_out=False
                                )
            # dns query packets
            self._contr.add_flow(datapath,
                                 2000,
                                 parser.OFPMatch(
                                     eth_src=nw_src,
                                     eth_dst=nw_dst,
                                     eth_type=Proto.ETHER_IP,
                                     ip_proto=Proto.IP_UDP,
                                     udp_dst=Proto.UDP_DNS,
                                     udp_src=src_port
                                 ),
                                 [parser.OFPInstructionActions(
                                     ofproto.OFPIT_APPLY_ACTIONS,
                                     [parser.OFPActionOutput(out_port)])],
                                 0,
                                 self._table_id_cf,
                                 msg=msg, in_port=in_port, idle_timeout=30, packet_out=False
                                )

        def install_http_nat(nw_src, nw_dst, ip_src, ip_dst, tcp_src, tcp_dst):
            """Adds flows that perform the http nat operation that redirects
                http requests to the portal webserver.
            """
            # TODO: we do not change port right now so it might collide with
            # other connections from the host. This is unlikely though

            self._logging.info("NAT-ing ")
            self._contr.logger.info("Natting")

            # Reverse rule goes first
            match = parser.OFPMatch(
                in_port=config.AUTH_SERVER_PORT,
                eth_src=config.AUTH_SERVER_MAC,
                eth_dst=nw_src,
                eth_type=Proto.ETHER_IP,
                ip_proto=Proto.IP_TCP,
                ipv4_src=config.AUTH_SERVER_IP,
                ipv4_dst=ip_src,
                tcp_dst=tcp_src,
                tcp_src=tcp_dst,
                )

            self._contr.add_flow(datapath,
                                 1000,
                                 match,
                                 [parser.OFPInstructionActions(
                                     ofproto.OFPIT_APPLY_ACTIONS,
                                     [parser.OFPActionSetField(ipv4_src=ip_dst),
                                      parser.OFPActionSetField(eth_src=nw_dst),
                                      parser.OFPActionOutput(in_port)
                                     ])
                                 ],
                                 0,
                                 self._table_id_cf,
                                 idle_timeout=30
                                )

            self._logging.debug("reverse match: %s", match)

            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=nw_src,
                eth_dst=nw_dst,
                eth_type=Proto.ETHER_IP,
                ip_proto=Proto.IP_TCP,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst,
                tcp_dst=tcp_dst,
                tcp_src=tcp_src,
                )
            self._logging.info("forward match %s", match)
            # Forward rule
            self._contr.add_flow(datapath,
                                 1001,
                                 match,
                                 [parser.OFPInstructionActions(
                                     ofproto.OFPIT_APPLY_ACTIONS,
                                     [parser.OFPActionSetField(ipv4_dst=config.AUTH_SERVER_IP),
                                      parser.OFPActionSetField(eth_dst=config.AUTH_SERVER_MAC),
                                      parser.OFPActionOutput(config.AUTH_SERVER_PORT)]
                                     )
                                 ],
                                 0,
                                 self._table_id_cf,
                                 msg=msg, in_port=in_port, idle_timeout=30
                                )

        def drop_unknown_ip(nw_src, nw_dst, ip_proto):
            """Adds flow that drops packets, that match the MAC source and destination and ip protocol.
            """
            self._contr.add_flow(datapath,
                                 10,
                                 parser.OFPMatch(
                                     eth_src=nw_src,
                                     eth_dst=nw_dst,
                                     eth_type=Proto.ETHER_IP,
                                     ip_proto=ip_proto,
                                     ),
                                 [],
                                 0,
                                 self._table_id_cf,
                                 msg=msg, in_port=in_port,
                                )

        if eth.ethertype != Proto.ETHER_IP:
            self._logging.info("      not handling non-ip traffic")
            return

        ip = pkt.get_protocol(ipv4.ipv4)

        # Is this communication allowed?
        # Allow if both src/dst are authenticated and

        if self.is_l2_traffic_allowed(nw_src, nw_dst, ip):
            self._logging.info("%s and %s is authenticated, installing bypass", nw_src, nw_dst)
            
            self.approve_user(datapath, parser, nw_src, nw_dst)
            return

        # Client authenticated but destination not, just block it
        if self.authenticate[ip.src]:
            self._logging.info("Auth client sending to non-auth destination blocked! " +
                                    str(ip.dst))
            self._logging.info("packet type %s, eth.dst %s, eth.src %s",
                                    ip.proto, eth.dst, eth.src)
            self._logging.info("ip.dst %s ip.src %s", ip.dst, ip.src)
            self._logging.info("gateway mac: %s", config.GATEWAY_MAC)
            return

        # Client is not authenticated
        if ip.proto == 1:
            self._logging.info("      ICMP, ignore")
            return

        if ip.proto == Proto.IP_UDP:
            _udp = pkt.get_protocol(udp.udp)
            if _udp.dst_port == Proto.UDP_DNS or _udp.src_port == Proto.UDP_DNS:
                self._logging.info("Install DNS bypass")
                install_dns_fwd(nw_src, nw_dst, out_port, _udp.src_port)
            else:
                self._logging.info("Unknown UDP proto, ignore, port: " + str(_udp.dst_port))
                return

        elif ip.proto == Proto.IP_TCP:
            _tcp = pkt.get_protocol(tcp.tcp)
            if _tcp.dst_port == Proto.TCP_HTTP:
                self._logging.info("Is HTTP traffic, installing NAT entry. in interface: %d", in_port)
                self._logging.info("ip.src: %s ip.dst: %s", ip.src, ip.dst)
                install_http_nat(nw_src, nw_dst, ip.src, ip.dst,
                                 _tcp.src_port, _tcp.dst_port)
        else:
            self._logging.info("Unknown IP proto: " + ip.proto + ", dropping")
            drop_unknown_ip(nw_src, nw_dst, ip.proto)

    def deal_with_arp(self, datapath, msg, pkt, eth, in_port, nw_dst, nw_src):
        """If the packet 'pkt' is an ARP packet handles it appropriately. 
            Returns true if pkt is ARP, false otherwise
        """
        # pass ARP through, defaults to flooding if destination unknown
        if eth.ethertype == Proto.ETHER_ARP:
            arp_pkt = pkt.get_protocols(arp.arp)[0]
            self._logging.info("ARP packet: dpid %s, mac_src %s, arp_ip_src %s, arp_ip_dst %s, in_port %s",
                                    datapath.id, nw_src, arp_pkt.src_ip,
                                    arp_pkt.dst_ip, in_port)

            port = self.mac_to_port[datapath.id].get(nw_dst, datapath.ofproto.OFPP_FLOOD)
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=[datapath.ofproto_parser.OFPActionOutput(port)],
                #actions=[datapath.ofproto_parser.OFPInstructionGotoTable(4)], #TODO
                data=msg.data)
            if port == datapath.ofproto.OFPP_FLOOD:
                self._logging.info("Flooding")
            else:
                self._logging.info("ARP out Port" + str(port))
            datapath.send_msg(out)
            return True
        return False

    def deal_with_dhcp(self, datapath, msg, pkt, eth, in_port, nw_dst):
        """Works out if a packet is dhcp and then handles it appropriately.
            Returns true if the packet was dhcp and therefore has been dealt with.
            False otherwise.
        """
        if eth.ethertype == Proto.ETHER_IP:
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            if ip.proto == Proto.IP_UDP:
                dh = None
                try:
                    dh = pkt.get_protocols(dhcp.dhcp)[0]

                    if dh is not None:
                        parser = datapath.ofproto_parser
                        self._logging.info("this is a dhcp packet")
                        if dh.op == 1:
                            # request
                            self._logging.info("sending dhcp request to gateway")
                            # allow the dhcp request/discover
                            out = parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=[parser.OFPActionOutput(config.GATEWAY_PORT)],
                                data=msg.data)

                            datapath.send_msg(out)
                            return True
                        elif dh.op == 2:
                            self._logging.info("dhcp reply, flooding if unknown dest")
                            # todo change this so we dont flood.
                            port = None
                            if nw_dst == "ff:ff:ff:ff:ff:ff":
                                port = datapath.ofproto.OFPP_FLOOD
                            else:
                                port = self.mac_to_port[datapath.id][nw_dst]

                            out = parser.OFPPacketOut(
                                datapath=datapath,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=[parser.OFPActionOutput(port)],
                                data=msg.data)

                            datapath.send_msg(out)
                            return True

                    else:
                        self._logging.info("this wasnt a dhcp packet")
                except IndexError:
                    # no DHCP packet, so continue down the line
                    pass

        return False

    def is_l2_traffic_allowed(self, nw_src, nw_dst, ip):
        """Returns True if the two mac address are allowed to communicate.
        """
        l2_traffic_is_allowed = False
        for entry in config.WHITELIST:
            if nw_src == entry[0] and nw_dst == entry[1]:
                l2_traffic_is_allowed = True
        if self.authenticate[ip.src] is True and self.authenticate[ip.dst] is True:
            self.ip_to_mac[ip.src] = nw_src
            self.ip_to_mac[ip.dst] = nw_dst
            l2_traffic_is_allowed = True
        if self.authenticate[ip.src] is True and nw_dst == config.GATEWAY_MAC:
           self.ip_to_mac[ip.src] = nw_src
           l2_traffic_is_allowed = True
        if nw_src == config.GATEWAY_MAC and self.authenticate[ip.dst] is True:
            self.ip_to_mac[ip.dst] = nw_dst
            l2_traffic_is_allowed = True

        if self.authenticate[ip.src] is True and nw_dst == config.AUTH_SERVER_MAC:
           self.ip_to_mac[ip.src] = nw_src
           l2_traffic_is_allowed = True
        if nw_src == config.AUTH_SERVER_MAC and self.authenticate[ip.dst] is True:
           self.ip_to_mac[ip.dst] = nw_dst
           l2_traffic_is_allowed = True

        self._logging.debug("l2 traffic is allowed: %s", l2_traffic_is_allowed)

        return l2_traffic_is_allowed

    def switch_features(self, event):
        """Process a switch features event from the controller.

        :param event: The OpenFlow event.
        """
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # self._logging.info("Clear rule table")

        # command = ofproto.OFPFC_DELETE

        # mod = parser.OFPFlowMod(datapath=datapath, match=parser.OFPMatch(), command=command,
        #                         out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
        #                        )
        # datapath.send_msg(mod)

        # Send everything to ctrl

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self._contr.add_flow(datapath, 1, match, inst, 0, self._table_id_cf)

        # So we don't need to learn auth server location
        # TODO: this assumes we are controlling only a single switch!
        port = config.AUTH_SERVER_PORT
        self.mac_to_port[datapath.id][config.AUTH_SERVER_MAC] = port

    def approve_user(self, datapath, parser, nw_src, nw_dst):
        """Adds flows that forwards the packets to the next table in the pipeline
        """

        self._contr.add_flow(datapath,
                             50000,
                             parser.OFPMatch(eth_src=nw_src,
                                             eth_dst=nw_dst),
                             [parser.OFPInstructionGotoTable(self.next_table)],
                             0,
                             self._table_id_cf, packet_out=False
                            )
        self._contr.add_flow(datapath,
                             50000,
                             parser.OFPMatch(eth_src=nw_dst,
                                             eth_dst=nw_src),
                             [parser.OFPInstructionGotoTable(self.next_table)],
                             0,
                             self._table_id_cf, packet_out=False
                            )

    def get_app_name(self):
        """Returns the name of the application.
        """
        return self._APP_NAME

    def get_expected_handlers(self):
        """Returns a list expected event handlers.
        """
        return self._EXPECTED_HANDLERS

    def is_supported(self):
        """Is the app supported.
        """
        return self._supported

    def _verify_contr_handlers(self):
        """Check if the controller can handle the event handlers needed by this application.
        """
        contr_handlers = self._contr.get_ofpe_handlers()
        failures = ()
        for expected_h in self._EXPECTED_HANDLERS:
            if expected_h not in contr_handlers:
                failures = failures + (expected_h,)
        if not len(failures) == 0:
            self._logging.error("%s: The following OpenFlow protocol events are not "
                  "supported by the controller:", self._APP_NAME)
            for f in failures:
                self._logging.error("\t- %s", str(f))
            return False
        else:
            return True
