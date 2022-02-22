# acl-dhcp
Program to maintain ACL through DHCP

Usage: acl-dhcp [-i <interface>] [-m <MAC address>] [-r <DHCP renew interval in sec>] [-g <gateway IP address>] start|stop|restart|status|log

*-i* is to provide the network interface to use (eth0, brwan, …).
*-m* is to provide the MAC address to use to obtain the ACL, default is MAC of the interface given.
*-r* is to provide a specified renewal interval between DHCP requests, default is standard DHCP renewing time (1/2 the lease duration).
*-g* is to provide manually the gateway (or router) IP to check via ARP that the connection is alive, default is router IP  provided by the DHCP server.

**start** is to start the daemon, -i is then mandatory. If the daemon is already running, it won't continue and the running instance will be kept.
**stop** is to stop the daemon, no other arguments are necessary.
**restart** is to start the daemon, -i is then mandatory. If the daemon is already running, it will stop it before launching the new instance.
**status** is to get the current status of the daemon, no other arguments are necessary.
**log** is to show the log, no other arguments are necessary.
