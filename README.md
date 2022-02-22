# acl-dhcp

Usage: acl-dhcp [-i *interface*] [-m *MAC address*] [-r *DHCP renew interval (in sec)*] [-g *gateway IP address*] start|stop|restart|status|log

*-i*  to provide the network interface to use (eth0, brwan, …).
  
*-m* to provide the MAC address to use to obtain the ACL, default is MAC of the interface given.
  
*-r* to provide a specified renewal interval between DHCP requests, default is standard DHCP renewing time (1/2 the lease duration).
  
*-g*  to provide manually the gateway (or router) IP to check via ARP that the connection is alive, default is router IP  provided by the DHCP server.

**start**  to start the daemon, -i is then mandatory. If the daemon is already running, it won't continue and the running instance will be kept.
  
**stop**  to stop the daemon, no other arguments are necessary.
  
**restart**  to start the daemon, -i is then mandatory. If the daemon is already running, it will stop it before launching the new instance.
  
**status**  to get the current status of the daemon, no other arguments are necessary.
  
**log**  to show the log, no other arguments are necessary.
