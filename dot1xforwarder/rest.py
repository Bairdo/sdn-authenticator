"""
    This file contains the REST class for the 802.1X controller.
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
import socket

from webob import Response
from ryu.app.wsgi import ControllerBase

class UserController(ControllerBase):
    """The REST class, that accepts requests for the user that is tryin to authenticate using 802.1X
    """
    def __init__(self, req, link, data, **config):
        super(UserController, self).__init__(req, link, data, **config)
        self.dpList = data
        
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
        
        self._logging.info("Started Dot1XForwarder's REST interface...");

    @staticmethod
    def register(wsgi):

        s = wsgi.mapper.submapper(controller=UserController)
        s.connect('idle', '/idle', action='idle_post',
                  conditions=dict(method=['POST']))

        s.connect('auth', '/authenticate/auth', action="authenticate_post", conditions=dict(method=['POST']))
        s.connect('auth', '/authenticate/auth', action="authenticate_delete", conditions=dict(method=['DELETE']))


    def authenticate_post(self, req, **kwargs):
        try:
            authJSON = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON")
       
        self._logging.info("POST with JSON, MAC: %s, User: %s", authJSON['mac'], authJSON['user'])
        self.dpList.new_client(authJSON['mac'], authJSON['user'])
        return Response(status=200)
      

    def idle_post(self, req, **_kwargs):
        """the REST endpoint for an HTTP POST when the client has been idle.
        """
        try:
            authJSON = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON")
        mac = authJSON['mac']
        user = authJSON['user']
        retrans = authJSON['retrans']

        self._logging.info("retrans: %s, MAC: %s, user: %s", str(retrans), mac, user)
        self.dpList.idle_mac(mac, retrans)

    @staticmethod
    def validate(address):
        """is the ip address given an actual IP address.
        """
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def authenticate_delete(self, req, **_kwargs):
        try:
            authJSON = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON")
       # TODO
        user = authJSON['user']
        mac = authJSON['mac']
      
        self.dpList.log_client_off(mac, user)
        self._logging.info("User %s at mac %s should now logged off.", user, mac)
        return Response(status=200)
