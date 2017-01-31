# sdn-authenticator
A SDN Controller application that allows authentication via 802.1X and a Captive Portal

This application is made up of 5 general components as shown in the diagram below: a Host (end user), portal server (authentication servers), the Internet, OpenFlow Controller, and an OpenFlow 1.3 capable switch.

The **Host** must either support 802.1X authentication or have a web browser/make HTTP requests. 
This has been tested with Windows 7, and Ubuntu 16.04 (with [wpa_supplicant](https://w1.fi/wpa_supplicant/) providing 802.1X support, and Firefox and Google Chrome Web Browsers).
Current limitation is that a 'true multi OpenFlow switch' topology is not supported YET (where there are multiple OpenFlow switches).
However the topology can be expanded with traditional dumb layer 2 switches (the switch must be able to forward 802.1X packets), but this will not disallow communication within your network.

The **Portal** acts as an authenticator for the 802.1X protocol and a webserver for the captive portal.

The **Internet** provides access to the Internet and at this stage DHCP and DNS servers (which are used by the captive portal).

The **Controller** is the [Ryu](http://osrg.github.io/ryu/) OpenFlow controller. As part of the controller, an HTTP server runs on the same machine so that the controller and the portal may communicate. 

The **OpenFlow Switch** is an OpenFlow 1.3 switch, we have used a [Northbound Networks Zodiac FX](http://northboundnetworks.com), [Allied Telesis ATx930](http://www.alliedtelesis.com/products/x930-series), and [OpenVSwitch](http://openvswitch.org).




## Install:

### Controller
Follow the installation with CapFlow and ACLSwitch Controller in https://github.com/libunamari/faucet/blob/master/README.rst

Follow the dependency steps in https://github.com/Bairdo/ACLSwitch-1

####Configure:

capflow/config.py contains IP/MAC addresses which are system dependant.

dot1xforwarder/dot1xforwarder.py lines 45-47 have the switch ports that are used by the openflow switch.

Run:
$ ryu-manager <path to>/Ryu_applicaiton/controller.py

#### HTTP Server
The server uses files and signals to indicate a change has happened with the users. Dot1xforwarder has two config files, one for active hosts and the other for idle hosts. Both files are CSV. As for CapFlow, there is only one config file: the currently authenticated users. The server sends a signal to the controller when a change occurs

The configuratiion filenames and location can be modified by setting environment variables. This can be set by the command: 

```
export CAPFLOW_CONFIG=/home/ubuntu/capflow_config.txt
```

|                | Default config filename                                 | Environment Variable                | Signal  |
|----------------|---------------------------------------------------------|-------------------------------------|---------|
| Capflow        | /etc/ryu/capflow_config.txt                             | CAPFLOW_CONFIG                      | SIGUSR2 |
| Dot1xforwarder | /etc/ryu/1x_active_users.txt /etc/ryu/1x_idle_users.txt | DOT1X_ACTIVE_HOSTS DOT1X_IDLE_HOSTS | SIGUSR1 |


### Portal:
  * you will also need to install the custom hostapd found here: https://github.com/Bairdo/hostapd-d1xf
  * and the webserver for the captive portal https://github.com/Bairdo/sdn-authenticator-webserver

    follow their instructions respectively.


