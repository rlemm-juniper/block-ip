block-ip.py was written for the Juniper SRX series to block a source IP Address that matches flow criteria based on destination-address, destination-port and application.  The script is argument-based and requires an entry for destination-address, port and application.  In order for the script to be effective, a policy is required to be positioned above the policy allowing access to the resource.  The policy must contain the address-object “blocked-addresses” denying access to the protected resource (destination-address).  A single firewall can be specified using the -d argument or you can use the -l argument with a text file containing a list of IP Addresses.  If no file is specified, iplist.txt will be used as a default.  Login credentials can be specified with -u and -pw.  Certificate login can be used with -c.  Below is a screenshot of the arguments and usage example: 

usage: block-ip.py [-h] [-d D] -i I [-l L] -a
                   {ah,egp,esp,gre,icmp,icmp6,igmp,ipip,ospf,pim,rsvp,sctp,tcp,udp}
                   [-u U] -p P [-c] [-pw PW]

optional arguments:
  -h, --help            show this help message and exit
  -d D                  Specify Device. Must be separately used from the -l
                        option
  -i I                  Destination IP-Address - Example: 192.168.0.1
  -l L                  Specify file containing Device-IP's (example: -l
                        filename.txt). If filename not specified, iplist.txt
                        will be used as default. Must be used separately from
                        the -d option
  -a {ah,egp,esp,gre,icmp,icmp6,igmp,ipip,ospf,pim,rsvp,sctp,tcp,udp}
                        Application - Acceptable Values: ah, egp, esp, gre,
                        icmp, icmp6, igmp, ipip, ospf, pim, rsvp, sctp, tcp,
                        udp
  -u U                  Login with username - If -pw is not specified, you
                        will be prompted for password
  -p P                  Destination Port - Range 1-65535
  -c                    Login with Device Certificate - No Additional input
                        required
  -pw PW                Login with password - If -u is not specified, you will
                        be prompted for username


Example:

Certificate Login:

./block-ip.py -d 10.10.1.1 -i 192.168.0.105 -p 22 -a tcp -c


Username/Password Login:

./block-ip.py -d 10.10.1.1 -i 192.168.0.105 -p 22 -a tcp -u root -pw password
