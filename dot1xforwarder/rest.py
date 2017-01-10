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
from ryu.app.wsgi import route

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
        route_name = 'authenticate'
        uri = '/v1.0/authenticate'
        uri += '/mac={mac}&user={user}'
        s = wsgi.mapper.submapper(controller=UserController)
#        s.connect(route_name, uri, action='post',
 #                 conditions=dict(method=['POST']))
        s.connect(route_name, uri, action='put',
                  conditions=dict(method=['PUT']))
        s.connect(route_name, uri, action='delete',
                  conditions=dict(method=['DELETE']))

        route_name = 'idle'
        uri = '/v1.0/idle'
        uri += '/retrans={retrans}&mac={mac}&user={user}'
        s = wsgi.mapper.submapper(controller=UserController)
        s.connect(route_name, uri, action='idle_post',
                  conditions=dict(method=['POST']))

        s.connect('auth', '/authenticate/auth', action="authenticate_post", conditions=dict(method=['POST']))

#    @route("authenticate", '/authenticate/auth', methods=["POST"])
    def authenticate_post(self, req, **kwargs):
        try:
            authJSON = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON")
        print authJSON
        self._logging.info("POST with JSON, MAC: %s, User: %s", authJSON['mac'], authJSON['user'])
        self.dpList.new_client(authJSON['mac'], authJSON['user'])
        return Response(status=200)
      



    def idle_post(self, req, retrans, mac, user, **_kwargs):
        """the REST endpoint for an HTTP POST when the client has been idle.
        """
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

    def post1(self, req, mac, user, **_kwargs):
        self.dpList.new_client(mac, user)
        self._logging.info("POST received for MAC: %s, User: %s", mac, user)
        return Response(status=200)

    def put(self, req, mac, user, **_kwargs):
        # TODO
        return Response(status=200)

    def delete(self, req, mac, user, **_kwargs):
        # TODO
        print "TODO HTTP Delete : " + user + " " + mac
        self.dpList.log_client_off(mac, user)
        self._logging.info("User %s at mac %s should now logged off.", user, mac)
        return Response(status=200)
