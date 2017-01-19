# sdn-authenticator
A SDN Controller application that allows authentication via 802.1X and a Captive Portal

This application is made up of 5 general components as shown in the diagram below: a Host (end user), portal server (authentication servers), the Internet, OpenFlow Controller, and an OpenFlow 1.3 capable switch.

The **Host** must either support 802.1X authentication or have a web browser/make HTTP requests. 
This has been tested with Windows 7, and Ubuntu 16.04 (with [wpa_supplicant](https://w1.fi/wpa_supplicant/) providing 802.1X support, and Firefox and Google Chrome Web Browsers).
Current limitation is that a 'true multi OpenFlow switch' topology is not supported YET (where there are multiple OpenFlow switches).
However the topology can be expanded with traditional dumb layer 2 switches (the switch must be able to forward 802.1X packets), but this will not disallow communication within your network.

The **Portal** acts as an authenticator for the 802.1X protocol and a webserver for the captive portal.

The **Internet** provides access to the Internet and at this stage DHCP and DNS servers (which are used by the captive portal).

The **Controller** is the [Ryu](http://osrg.github.io/ryu/) OpenFlow controller.

The **OpenFlow Switch** is an OpenFlow 1.3 switch, we have used a [Northbound Networks Zodiac FX](http://northboundnetworks.com), [Allied Telesis ATx930](http://www.alliedtelesis.com/products/x930-series), and [OpenVSwitch](http://openvswitch.org).





## Install:

### Controller:
```$ pip install ryu

$ git clone https://github.com/Bairdo/sdn-authenticator.git

$ git clone https://github.com/Bairdo/ACLSwitch-1.git
```

Follow the dependency steps in https://github.com/Bairdo/ACLSwitch-1

Change the table that [Ryu_Application/l2switch/l2switch.py](https://github.com/Bairdo/ACLSwitch-1/blob/master/Ryu_Application/l2switch/l2switch.py#L62) "self._table_id_l2" uses ~line 62 to = 4.

Change the tables that [Ryu_Application/aclswitch/aclswitch.py]() ~line 86
  so that:

      self._table_id_blacklist = 2

      self._table_id_whitelist = 3

      self._table_id_next = 4

In [Ryu_Application/controller.py](https://github.com/Bairdo/ACLSwitch-1/blob/master/Ryu_Application/controller.py#L58) add
```
self._register_app(Dot1Forwarder(self))
self._register_app(CapFlow(self)
```

and the imports in the top section of file
```
from authenticators.dot1xforwarder.dot1xforwarder import Dot1XForwarder
from authenticators.capflow.CapFlow import CapFlow
```

change directory into ACLSwitch/Ryu_Application

$ ln -s ~/sdn-authenticator/ authenticators

####Configure:

capflow/config.py contains IP/MAC addresses which are system dependant.

dot1xforwarder/dot1xforwarder.py lines 45-47 have the switch ports that are used by the openflow switch.

Run:
$ ryu-manager <path to>/Ryu_applicaiton/controller.py


### Portal:
  * you will also need to install the custom hostapd found here: https://github.com/Bairdo/hostapd-d1xf
  * and the webserver for the captive portal https://github.com/Bairdo/sdn-authenticator-webserver

    follow their instructions respectively.


