# sdn-authenticator
A SDN Controller application that allow authentication via 802.1X and a Captive Portal


Install:

$ pip install ryu

$ git clone https://github.com/Bairdo/sdn-authenticator.git

$ git clone https://github.com/Bairdo/ACLSwitch-1.git

Follow the dependency steps in https://github.com/Bairdo/ACLSwitch-1

Change the table that Ryu_Application/l2switch/l2switch.py "self._table_id_l2" uses ~line 62 to = 4.

Change the tables that Ryu_Application/aclswitch/aclswitch.py ~line 86
  so that:

      self._table_id_blacklist = 2

      self._table_id_whitelist = 3

      self._table_id_next = 4

change directory into ACLSwitch/Ryu_Application

$ ln -s ~/sdn-authenticator/ authenticators


On the "portal":
  - you will also need to install the custom hostapd found here: https://github.com/Bairdo/hostapd-d1xf
  
    follow its instructions to install
  - and the webserver for the captive portal.
      - # apt-get install gunicorn
      - # copy capflow directory from here to portal.
      - # to start the portal webserver:
          $ cd capflow/mininet
          # ./start-captive
          or just run the command in that script directly.



Configure:

capflow/config.py contains IP/MAC addresses which are system dependant.

dot1xforwarder/dot1xforwarder.py lines 45-47 have the switch ports that are used by the openflow switch.

Run:
$ ryu-manager <path to>/Ryu_applicaiton/controller.py
