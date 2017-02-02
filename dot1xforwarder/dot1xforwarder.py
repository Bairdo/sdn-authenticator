"""
    This file contains the controller logic for the app that controls the 802.1X authentication.
    There is a REST interface class in the same package 'rest.py'.
"""
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = 'Michael Baird'

import collections
import json
import logging
import os
import signal
import fcntl
import urllib2

from ryu.controller.ofp_event import EventOFPPacketIn
from ryu.controller.ofp_event import EventOFPSwitchFeatures
from ryu.controller import dpset
from ryu.controller import event
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import dhcp
from ryu.lib.packet import udp
# Ryu - REST API
from ryu.app.wsgi import WSGIApplication

from abc_ryu_app import ABCRyuApp
from rest import UserController

from faucet.util import get_sys_prefix
import lockfile

R2_PRIORITY = 5100
ACCESS_PORT = 4
PORTAL_PORT = 2

NETMASK = "255.255.255.0"
NETWORK_ADDRESS = "10.0.0.0"

class EventDot1xUserChange(event.EventBase):
    """Event used to indicate a change in config files"""
    pass

class Proto(object):
    """Class for protocol numbers
    """
    ETHER_IP = 0x0800
    EAPOL = 0x888e
    DHCP_SERVER_DST = 67
    DHCP_CLIENT_DST = 68
    IP_UDP=17

class DpList(object):
    """Class that is used for communication between the REST interface and the controller.
    """
    def __init__(self, d1xf, contr, table_id, blacklist_table, l2switch_table,
                 *args, **kwargs):
        self.datapaths = []
        self._table_id_1x = table_id
        self._blacklist_table = blacklist_table
        self._l2switch_table = l2switch_table
        self._contr = contr
        self._d1xf = d1xf
        print "TODO should actually use ryu's dpset for getting the datapaths connected to this controller."

    def idle_mac(self, mac, retrans_count):
        """make the client use the captive portal, if they are not responding to attempts to use 1X
        """
        self._d1xf.make_client_use_portal(mac, retrans_count)
	#print "enable captive portal fallback again."

    def append(self, dp):
        """Add the datapath to the list of datapaths.
        """
        self.datapaths.append(dp)

    def log_client_off(self, mac, user):
        """A client has logged off.
            Here or in the dot1xforwarder main we need to remove the rules that a user is using.
        """
        self._d1xf.log_client_off(mac, user)

    def new_client(self, mac, user):
        """New client has been authorised, add the flows to work out the IP address.
        """
        self._d1xf.add_new_client(mac, user)
        print "TODO user not implemented yet"


class Dot1XForwarder(ABCRyuApp):
    """Class that controls the 802.1X process.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
#        'dpset': dpset.DPSet,
        #'wsgi': WSGIApplication
    }

    _APP_NAME = "Dot1XForwarder"
    _EXPECTED_HANDLERS = (EventOFPSwitchFeatures.__name__, 
                          EventOFPPacketIn.__name__,
                          EventDot1xUserChange.__name__)

    def __init__(self, contr, *args, **kwargs):
        super(Dot1XForwarder, self).__init__()
        self._contr = contr
        self._table_id_1x = 0
        self.capflow_table = 1
        self.blacklist_table = 2
        self.l2_switch_table = 2
        self._supported = self._verify_contr_handlers()

        self.datapaths = []
        self.mac_to_ip = collections.defaultdict(dict)
        self.ip_to_mac = collections.defaultdict(dict)
        self.authed_ip_by_mac = collections.defaultdict(dict)

        self.authenicated_mac_to_user = collections.defaultdict(dict)

        self.authenticate = collections.defaultdict(dict)
        self.dpList = DpList(self, self._contr, self._table_id_1x,
                             self.blacklist_table, self.l2_switch_table)

        #self._contr._wsgi.registory['UserController'] = self.dpList
        #UserController.register(self._contr._wsgi)
        
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

        self._logging.info("Started Dot1XForwarder...");
        
        self.active_file = os.getenv('DOT1X_ACTIVE_HOSTS','/etc/ryu/1x_active_users.txt')
        self.idle_file = os.getenv('DOT1X_IDLE_HOSTS','/etc/ryu/1x_idle_users.txt')
        
        #clear the config files
        with open(self.active_file, 'w'): pass
        with open(self.idle_file, 'w'): pass

    def read_file(self,filename):
        dictionary = dict()
        with open(filename) as file_:
            for line in file_:
                currentline = line.split(",")
                dictionary[currentline[0]] = currentline[1].rstrip()
        return dictionary
    
    def check_active(self):
        """Check if the active hosts have changed        
        """
        
        #obtain a lock to the file so that no modifications are made while we process it
        fd = lockfile.lock(self.active_file, os.O_RDWR)
        active_users = self.read_file(self.active_file)
        #release the lock
        lockfile.unlock(fd)
        
        #check for new users by taking the difference of the users from the file and the authenticated users
        new_users = { k : active_users[k] for k in set(active_users) - set(self.authenicated_mac_to_user) }
        for mac,usr in new_users.iteritems():
            print "new mac " + mac + " user: " + usr
            self.add_new_client(mac,usr)
        
        #check for for the log off of users by seeing if the mac,user has been removed from the file
        log_off_users = { k : self.authenicated_mac_to_user[k] for k in set(self.authenicated_mac_to_user) - set(active_users) }
        for mac,usr in log_off_users.iteritems():
            self.log_client_off(mac,usr)
    
    def check_idle(self):
        """ Check if there are any new idle hosts that need to be processed        
        """
        fd = lockfile.lock(self.idle_file, os.O_RDWR)
        idle_users = self.read_file(self.idle_file)
        #clear the file since we have read in the idle hosts already
        os.ftruncate(fd,0)
        lockfile.unlock(fd)
        
        for mac,retry in idle_users.iteritems():
            self.make_client_use_portal(mac,retry)
        
    def reload_config(self,event):
        """Reload the config files, both the active hosts and the idle hosts 
        """
        self.check_active()
        self.check_idle()
                
    def add_new_client(self, mac, user):
        """New user has been authenticated with the given MAC address.
        """
        # todo deal with user.
        self.authenicated_mac_to_user[mac] = user
        
        for d in self.datapaths:
            ofproto = d.ofproto
            parser = d.ofproto_parser

            # allow all level 2 traffic through let l2switch handle the where.
            # this rule will allow arp and dhcp to go through.
            match = parser.OFPMatch(eth_dst=mac)
            actions = parser.OFPInstructionGotoTable(self.l2_switch_table)
            inst = [actions]
            self._contr.add_flow(d, 5001, match, inst, 0, self._table_id_1x, cookie=0x01)

            match = parser.OFPMatch(eth_src=mac)
            actions = parser.OFPInstructionGotoTable(self.l2_switch_table)
            inst = [actions]
            self._contr.add_flow(d, 5002, match, inst, 0, self._table_id_1x, cookie=0x02)
            match = parser.OFPMatch(eth_dst=mac)
            
            
            actions = parser.OFPInstructionGotoTable(self.l2_switch_table)
            inst = [actions]
            match = parser.OFPMatch(eth_src=mac, eth_type=Proto.ETHER_IP, ip_proto=Proto.IP_UDP, udp_dst=Proto.DHCP_SERVER_DST)
            self._contr.add_flow(d, 5200, match, inst, 0, self._table_id_1x, cookie=0x20)

       	    match = parser.OFPMatch(eth_dst=mac, eth_type=Proto.ETHER_IP, ip_proto=Proto.IP_UDP, udp_dst=Proto.DHCP_CLIENT_DST)

            actions = parser.OFPInstructionGotoTable(self.l2_switch_table)
            inst = [actions]
            self._contr.add_flow(d, 5200, match, inst, 0, self._table_id_1x, cookie=0x21)
            
            # 'R2' rules
            # if is a ip packet on the known mac. send to controller as well.
            # once we have the ip address this mac is using, we delete this rule.
            # what if multiple ips on the interface though?

            # if src is local ip, and new ip. and dst is on the internet.
            match = parser.OFPMatch(eth_src=mac, eth_type=Proto.ETHER_IP,
                                    ipv4_src=(NETWORK_ADDRESS, NETMASK))
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._contr.add_flow(d, R2_PRIORITY+1, match, inst, 0, self._table_id_1x, cookie=0x03)

            # if dst is local ip, and new ip. and src is on the internet
            match = parser.OFPMatch(eth_dst=mac, eth_type=Proto.ETHER_IP,
                                    ipv4_dst=(NETWORK_ADDRESS, NETMASK))
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._contr.add_flow(d, R2_PRIORITY+2, match, inst, 0, self._table_id_1x, cookie=0x04)

            # if both dst and src is local ip, and new ip. might need a special case if both local.
            match = parser.OFPMatch(eth_dst=mac, eth_type=Proto.ETHER_IP,
                                    ipv4_src=(NETWORK_ADDRESS, NETMASK),
                                    ipv4_dst=(NETWORK_ADDRESS, NETMASK))
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._contr.add_flow(d, R2_PRIORITY+3, match, inst, 0, self._table_id_1x, cookie=0x05)

            match = parser.OFPMatch(eth_src=mac, eth_type=Proto.ETHER_IP,
                                    ipv4_src=(NETWORK_ADDRESS, NETMASK),
                                    ipv4_dst=(NETWORK_ADDRESS, NETMASK))
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._contr.add_flow(d, R2_PRIORITY+4, match, inst, 0, self._table_id_1x, cookie=0x06)

    def log_client_off(self, mac, user):
        if mac in self.authenicated_mac_to_user:
            del self.authenicated_mac_to_user[mac]
        if mac in self.authed_ip_by_mac:
            del self.authed_ip_by_mac[mac]

        for datapath in self._contr.get_all():
            datapath = datapath[1]

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(eth_dst=mac)
            self._contr.remove_flow(datapath,
                                    parser,
                                    self._table_id_1x,
                                    ofproto.OFPFC_DELETE, # could also be ofproto.OFPFC_DELETE_STRICT
                                    5001,
                                    match,
                                    ofproto.OFPP_ANY,
                                    ofproto.OFPG_ANY,
                                    cookie=0x01)

            match = parser.OFPMatch(eth_src=mac)
            self._contr.remove_flow(datapath,
                                    parser,
                                    self._table_id_1x,
                                    ofproto.OFPFC_DELETE, # could also be ofproto.OFPFC_DELETE_STRICT
                                    5002,
                                    match,
                                    ofproto.OFPP_ANY,
                                    ofproto.OFPG_ANY,
                                    cookie=0x02)
 
            match = parser.OFPMatch(eth_src=mac, eth_type=Proto.ETHER_IP)

            self._contr.remove_flow(datapath,
                                    parser,
                                    self._table_id_1x,
                                    ofproto.OFPFC_DELETE, # could also be ofproto.OFPFC_DELETE_STRICT
                                    5110,
                                    match,
                                    ofproto.OFPP_ANY,
                                    ofproto.OFPG_ANY,
                                    cookie=0x0d)

            match = parser.OFPMatch(eth_dst=mac, eth_type=Proto.ETHER_IP)
            self._contr.remove_flow(datapath,
                                    parser,
                                    self._table_id_1x,
                                    ofproto.OFPFC_DELETE, # could also be ofproto.OFPFC_DELETE_STRICT
                                    5110,
                                    match,
                                    ofproto.OFPP_ANY,
                                    ofproto.OFPG_ANY,
                                    cookie=0x0e)

    def switch_features(self, event):
        """Called when a switch connects to the controller.
        """

        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths.append(datapath)

        # all eap traffic goes to the portal nuc.
        match = parser.OFPMatch(eth_type=Proto.EAPOL)
        inst = [parser.OFPInstructionGotoTable(self.l2_switch_table)]

        self._contr.add_flow(datapath, 10000, match, inst, 0, self._table_id_1x, cookie=0x08)

#        match = parser.OFPMatch(eth_type=Proto.EAPOL)
#	inst = [parser.OFPInstructionGotoTable(self.l2_switch_table)]


#        self._contr.add_flow(datapath, 10000, match, inst, 0, self._table_id_1x, cookie=0x09)

        # drop unmatched traffic (this will be from internet)
        match = parser.OFPMatch()
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self._contr.add_flow(datapath, 0, match, inst, 0, self._table_id_1x, cookie=0x0a)
        
        # all traffic goes to the portal nuc. this is so we can trigger 802.1x.
        # which hostapd does by listening for dhcp only
#        match = parser.OFPMatch(in_port=PORTAL_PORT)
#        actions = [parser.OFPActionOutput(ACCESS_PORT)]
#        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
#                                             actions)]
#        self._contr.add_flow(datapath, 1000, match, inst, 0, self._table_id_1x, cookie=0x0b)

#        match = parser.OFPMatch(in_port=ACCESS_PORT)
#        actions = [parser.OFPActionOutput(PORTAL_PORT)]
#        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
#                                             actions)]
        self._contr.add_flow(datapath, 1000, match, inst, 0, self._table_id_1x, cookie=0x0c)

    def packet_in(self, event):
        """Called when the controller receives a packet in message from the switch
        """

        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(event.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # if self.mac_to_ip[eth.dst]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if event.msg.table_id != self._table_id_1x:
	    self._logging.debug("ignore packet from other tables %d, my table: %d", event.msg.table_id, self._table_id_1x)
	    return

        if ip_pkt is None:
            # packet in is only used for learning the ip address of a mac that
            # has authenticated with 802.1X. so drop everything else.
            return

        self._logging.info("Packet In ip_src: %s, ip_dst: %s", ip_pkt.src, ip_pkt.dst)
        #print "d1x " + str( packet.Packet(event.msg.data))
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # if it is a DHCP packet then forward it appropriatly.
        if udp_pkt is not None:
            # fix this.
            if udp_pkt.dst_port == Proto.DHCP_SERVER_DST:
	        self._logging.info("DHCP packet from client, sending to server")

                out = parser.OFPPacketOut(
                    datapath=datapath,
                    actions=[parser.OPFInstructionGotoTable(self.l2_switch_table)],
                    in_port=event.msg.match['in_port'],
                    buffer_id=0xffffffff,
                    data=event.msg.data)
                datapath.send_msg(out)
		return
            elif udp_pkt.dst_port == Proto.DHCP_CLIENT_DST:
		self._logging.info('DHCP packet from server, sending to the "access port"')
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    actions=[parser.OFPInstructionGotoTable(self.l2_switch_table)],
		    in_port=event.msg.match['in_port'],
                    buffer_id=0xffffffff,
                    data=event.msg.data)
                datapath.send_msg(out)
		return
            #else:
                #self._logging.warn("dont know how to deal with dhcp packet with unknown udp dest port")
            #return

        self.do_mac_ip_auth(datapath, parser, ofproto, eth.src, ip_pkt.src)
        self.do_mac_ip_auth(datapath, parser, ofproto, eth.dst, ip_pkt.dst)

        # if single ip is new and authenticated
        #   add rule
        # if both ip are new and authenticated
        #   add rule src
        #   add rule dst
        # if no ip are authed
        #   do nothing

    def is_mac_ip_authed(self, mac):
        """Is the mac address authenticated (returns true if they are)
        """
        self._logging.debug("authed-mac-to-user %s", self.authenicated_mac_to_user)
        if self.authenicated_mac_to_user[mac] != {}:
            self._logging.debug("authed-ip-by-mac %s", self.authed_ip_by_mac)
            if self.authed_ip_by_mac[mac] == {}:
                return True
            return True
        # the mac address could be not authenticated.
        # OR (mac could be authed and ip has already been dealt with).
        # TODO how should we deal with this?
        return False

    def do_mac_ip_auth(self, datapath, parser, ofproto, mac, ip):
        """If we learn the IP address of an already authenticated MAC then remove the rules already installed.
        """
        # if mac is authenticated but not already dealt with. add the rules
        
        print "authenticate IP"
        if self.is_mac_ip_authed(mac):
            self.authed_ip_by_mac[mac] = ip
            self.add_ip_authenticated_rules(datapath, parser, mac, ip)

            # remove 'R2' rule
            # 'R2' rules
            # if is a ip packet on the known mac. send to controller as well.
            # once we have the ip address this mac is using, we delete this rule.
            # what if multiple ips on the interface though?

            # if src is local ip, and new ip. and dst is on the internet.
            match = parser.OFPMatch(eth_src=mac, eth_type=Proto.ETHER_IP,
                                    ipv4_src=(NETWORK_ADDRESS, NETMASK))
            self._contr.remove_flow(datapath, parser, self._table_id_1x,
                                    ofproto.OFPFC_DELETE_STRICT, R2_PRIORITY+1,
                                    match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
            # if dst is local ip, and new ip. and src is on the internet
            match = parser.OFPMatch(eth_dst=mac, eth_type=Proto.ETHER_IP,
                                    ipv4_dst=(NETWORK_ADDRESS, NETMASK))
            self._contr.remove_flow(datapath, parser, self._table_id_1x,
                                    ofproto.OFPFC_DELETE_STRICT, R2_PRIORITY+2,
                                    match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

            # if both dst and src is local ip, and new ip. might need a special case if both local.
            match = parser.OFPMatch(eth_dst=mac, eth_type=Proto.ETHER_IP,
                                    ipv4_src=(NETWORK_ADDRESS, NETMASK),
                                    ipv4_dst=(NETWORK_ADDRESS, NETMASK))
            self._contr.remove_flow(datapath, parser, self._table_id_1x,
                                    ofproto.OFPFC_DELETE_STRICT, R2_PRIORITY+3,
                                    match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

            match = parser.OFPMatch(eth_src=mac, eth_type=Proto.ETHER_IP,
                                    ipv4_src=(NETWORK_ADDRESS, NETMASK),
                                    ipv4_dst=(NETWORK_ADDRESS, NETMASK))
            self._contr.remove_flow(datapath, parser, self._table_id_1x,
                                    ofproto.OFPFC_DELETE_STRICT, R2_PRIORITY+4,
                                    match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
	else:
	    self._logging.debug("mac %s isnt authenticated", mac)

    def add_ip_authenticated_rules(self, datapath, parser, mac, auth_ip):
        """Adds the rules for the authenticate IP address. (forward to blacklist table)
        """
        self._logging.debug("adding ip authenticated rules for ip: %s", auth_ip)
        # rules for single authed ip.
        match = parser.OFPMatch(eth_src=mac, eth_type=Proto.ETHER_IP, ipv4_src=auth_ip)
        inst = [parser.OFPInstructionGotoTable(self.blacklist_table)]
        self._contr.add_flow(datapath, 5110, match, inst, 0, self._table_id_1x, cookie=0x0d)

        match = parser.OFPMatch(eth_dst=mac, eth_type=Proto.ETHER_IP, ipv4_dst=auth_ip)
        inst = [parser.OFPInstructionGotoTable(self.blacklist_table)]
        self._contr.add_flow(datapath, 5110, match, inst, 0, self._table_id_1x, cookie=0x0e)

        self.send_user_rules(self.authenicated_mac_to_user[mac], auth_ip)
        
    def send_user_rules(self, user, ip):
        """Sends the rules for the user, to ACLSwitch. Also inserts the given IP address into the rules as required.
        """
        self._logging.debug("Sending rules to ACLSwitch for %s, ip: %s", user, ip)
        # get rules for user.
	
        directory = os.path.join(os.path.dirname(__file__),"..", "capflow/rules")
        rule_location = "{:s}/{:s}.rules.json".format(directory, user)

        acl_rules = dict()
        
        with open(rule_location) as user_rules:
            for line in user_rules:
                if line.startswith("#"):
                    continue
                rule = json.loads(line)
                if rule["rule"]['ip_src'] == "ip":
                    self._logging.debug("replacing ip_src")
                    match = OFPMatch(ipv4_src = ip, eth_type = 2048)
                if rule["rule"]['ip_dst'] == "ip":
                    self._logging.debug("replacing ip_dst")
                    match = OFPMatch(ipv4_dst = ip, eth_type = 2048)
                
                acl_rules[match] = 1
        self._contr.add_acl_rule(100, acl_rules)
        os.kill(os.getpid(),signal.SIGHUP)  

    def make_client_use_portal(self, mac, retrans_count):
        """Redirect the client to use the captive portal instead of 802.1X.
        """
        # add rule with highest priority for table 0, with this mac to go to table capflow

        # TODO need to deal with other datapaths.
        # TODO hostapd might only be sending when the retransmit count is >= 3 anyway.
        # but we might want to make it configurable from this application
        if retrans_count >= 2:
	    self._logging.info("Client %s will now use captive portal after retrans: %s", mac, retrans_count)
	    for datapath in self._contr.get_all():
#            datapath = self._contr.switch_get_datapath(123917682135244)
                datapath = datapath[1]
                print datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                match = parser.OFPMatch(eth_src=mac)
                inst = [parser.OFPInstructionGotoTable(self.capflow_table)]
                self._contr.add_flow(datapath, 20000, match, inst, 0, self._table_id_1x, cookie=0x0f)

                match = parser.OFPMatch(eth_dst=mac)
                inst = [parser.OFPInstructionGotoTable(self.capflow_table)]
                self._contr.add_flow(datapath, 20000, match, inst, 0, self._table_id_1x, cookie=0x10)

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
