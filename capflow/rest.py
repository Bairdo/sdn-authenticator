"""
    This file contains the REST class for the capflow (captive portal) controller.
"""
# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2012 Isaku Yamahata <yamahata at private email ne jp>
# Copyright (C) 2014 Joe Stringer < joe at wand net nz >
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

import json
import logging
import os
import socket
import urllib2
import signal

from webob import Response
from ryu.app.wsgi import ControllerBase

import lockfile
import psutil

class UserController2(ControllerBase):
    """The REST class, that accepts requests for the user that is tryin to authenticate using capflow (captive portal)
    """
    def __init__(self, req, link, data, **config):
        super(UserController2, self).__init__(req, link, data, **config)
        self.capflow_interface = data
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
        
        self._logging.info("Started CapFlow's REST interface...")
        self.config_file = os.getenv('CAPFLOW_CONFIG','/etc/ryu/capflow_config.txt')
        self._contr_pid = -1

    @staticmethod
    def register(wsgi):
        route_name = 'authenticate'
        uri = '/v1.0/authenticate'
        uri += '/ip={ip}&user={user}'
        s = wsgi.mapper.submapper(controller=UserController2)
        s.connect(route_name, uri, action='post',
                  conditions=dict(method=['POST']))
        s.connect(route_name, uri, action='put',
                  conditions=dict(method=['PUT']))
        s.connect(route_name, uri, action='delete',
                  conditions=dict(method=['DELETE']))
                  
    @staticmethod
    def validate(address):
        """is the ip address given an actual IP address.
        """
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def post(self, req, ip, user, **_kwargs):
        if not self.validate(ip):
            return Response(status=403)
        # if self.authenticate.get(ip, False) == True:
        #    print "IP already authenticated."
        #    return Response(status=200)
        self._logging.info("POST received ip: %s, user: %s", ip, user)
        ip = str(ip)

        #self.send_user_rules(user, ip)
        #self.capflow_interface.new_client(ip, user)
        fd = lockfile.lock(self.config_file, os.O_APPEND | os.O_WRONLY)
        os.write(fd, ip + "," + user + "\n")
        lockfile.unlock(fd)
        self.send_signal()
        return Response(status=200)

    def put(self, req, ip, user, **_kwargs):
        if not self.validate(ip):
            return Response(status=403)
        self._logging.info("PUT received ip: %s, user: %s", ip, user)
        ip = str(ip)
        #self.send_user_rules(user, ip)
        #self.capflow_interface.new_client(ip, user)
        fd = lockfile.lock(self.config_file, os.O_APPEND | os.O_WRONLY)
        os.write(fd, ip + "," + user + "\n")
        lockfile.unlock(fd)
        self.send_signal()
        return Response(status=200)

    def delete(self, req, ip, user, **_kwargs):
        if self.capflow_interface.is_authed(ip) is False:
            print "user already logged off"
            return Response(status=200)

        print "HTTP Delete : " + user + " " + ip
	# todo remove the flows somehow.

	self.capflow_interface.log_client_off(ip, user)

        return Response(status=200)

    def send_user_rules(self, user, ip):
        # get rules for user.
	directory = os.path.join(os.path.dirname(__file__), "rules")
        rule_location = "{:s}/{:s}.rules.json".format(directory, user)

        # for each rule in user.rules
        #    send rule to aclswitch via rest interface.
        with open(rule_location) as user_rules:
            for line in user_rules:
                if line.startswith("#"):
                    continue
                rule = json.loads(line)
		self._logging.info("rule: %s", rule)
                if rule["rule"]['ip_src'] == "ip":
                    rule["rule"]["ip_src"] = ip
                if rule["rule"]['ip_dst'] == "ip":
                    rule["rule"]['ip_dst'] = ip

                # rule["rule"]['time_enforce'] = ["0", "0"]
                #req = urllib2.Request('http://127.0.0.1:8080/aclswitch/acl')
                #req.add_header('Content-Type', 'application/json')
                #print rule
                #response = urllib2.urlopen(req, json.dumps(rule))

                #self._logging.info("%s",response)
    def send_signal(self):
        if self._contr_pid < 0:
            for process in psutil.process_iter():
                if process.name() == "ryu-manager" and any("controller.py" in s for s in process.cmdline()):
                    self._contr_pid = process.pid
                    break
        
        os.kill(self._contr_pid,signal.SIGUSR2)  
