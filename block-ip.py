#!/usr/bin/python

import argparse
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import cpu_count
import os
import sys
import getpass
import yaml
from jinja2 import Template
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import RpcError
from jnpr.junos.factory.factory_loader import FactoryLoader

YamlTable = \
    """---
    SessionTable:
      rpc:  get-flow-session-information
      item:  .//flow-session
      key:  session-identifier
      view:  SessionView

    SessionView:
      fields:
        re_name:  ../../re-name
        session_identifier:  session-identifier
      groups:
        in: flow-information[normalize-space(direction)='In']
        out: flow-information[normalize-space(direction)='Out']
      fields_in:
        in_source_address:  source-address
        in_destination_address:  destination-address
        in_destination_port:  destination-port
        in_session_protocol:  protocol
        in_session_direction:  direction
      fields_out:
        out_source_address:  source-address
        out_destination_address:  destination-address
        out_destination_port:  destination-port
        out_session_protocol:  protocol
        out_in_session_direction:  direction

    ClusterStatus:
      rpc:  get-chassis-cluster-status
      item: .//redundancy-group
      key:  redundancy-group-id
      view:  ClusterView

    ClusterView:
      fields:
        device_name:  device-stats/device-name
        redundancy_group_status:  device-stats/redundancy-group-status
        redundancy_group_id:  redundancy-group-id"""

globals().update(FactoryLoader().load(yaml.load(YamlTable)))

JinjaTemplate = Template('security { address-book { global { address {{ Address }}/32 {{ Address }}/32; address-set blocked-addresses { address {{ Address }}/32; } } } }')

results = ''
process_ip_list = []
cert = ''
onedevice = ''
destip = ''
uname = ''
upass = ''
dport = ''
application = ''

parser = argparse.ArgumentParser(add_help=True)


parser.add_argument("-d", action="store",
                    help="Specify Device.  Must be separately used from the -l option")

parser.add_argument("-i", action="store",
                    help="Destination IP-Address - Example: 192.168.0.1", required=True)

parser.add_argument("-l", action="store",
                    help="Specify file containing Device-IP's (example:  -l filename.txt).  If filename not specified, iplist.txt will be used as default.  Must be used separately from the -d option")

parser.add_argument("-a", action="store", choices=['ah', 'egp', 'esp', 'gre', 'icmp', 'icmp6', 'igmp', 'ipip', 'ospf', 'pim', 'rsvp', 'sctp', 'tcp', 'udp'],
                    help="Application - Acceptable Values: ah, egp, esp, gre, icmp, icmp6, igmp, ipip, ospf, pim, rsvp, sctp, tcp, udp", required=True)

parser.add_argument("-u", action="store",
                    help="Login with username - If -pw is not specified, you will be prompted for password")

parser.add_argument("-p", action="store",
                    help="Destination Port - Range 1-65535", required=True)

parser.add_argument("-c", action="store_false",
                    help="Login with Device Certificate - No Additional input required")

parser.add_argument("-pw", action="store",
                    help="Login with password - If -u is not specified, you will be prompted for username")

args = parser.parse_args()

if args.p > '65535' or args.p < '1':
    print "Please select a TCP Port between 1-65535"
    parser.print_help()
    sys.exit()
else:
    pass

if args.l and args.d:
    print " Do not specify -l and -d together."
    parser.print_help()
    sys.exit()
if args.c is False:
    cert = 1
if args.d:
    onedevice = args.d
    ip_list = []
    ip_list.append(onedevice)
if args.i:
    destip = args.i
if args.a:
    application = args.a
if args.l:
    iplist = args.l
    listips = open(iplist)
    with listips as f:
        ip_list = [line.rstrip() for line in f]
    listips.close()
elif not args.l and not args.d:
    with open('iplist.txt') as f:
        ip_list = [line.rstrip() for line in f]
if args.u:
    uname = args.u
if args.p:
    dport = args.p
if args.pw:
    upass = args.pw

jinja_data = open("jinjafile.conf", "wb")

def process_device(ip, **kwargs):
    dev = Device(host=ip, **kwargs)
    cu = Config(dev)
    print "Searching for active sessions on Device:", ip, "matching the following criteria" + '\n\n\t' + "Destination IP-Address:" + '\t' + destip + '\n\t' + "Destination-Port:" + '\t' +  dport + '\n\t' + "Application:" + '\t\t' +  application + '\n'

    try:

        dev.open()
        cluster_status = ClusterStatus(dev)
        cluster_status.get()
        session_table = SessionTable(dev)
        session_table.get()
        found = 'f'
        cluster = 'a'
        cu.lock()

        for c in cluster_status:
          if cluster_status.keys():
            print "SRX Cluster has redundancy-group", c.redundancy_group_id
          if not cluster_status.keys():
            print "Clustering is not Enabled"

        for s in session_table:
          if session_table.keys() and s.in_destination_address == destip and s.in_destination_port == dport and s.in_session_protocol == application:
            found = 't'
            print "Found Session on", ip, s.re_name  + '\n\n\t' + "Source-Address:" + '\t' + s.in_source_address +'\n\t' + "Session-Id:" + '\t' + s.session_identifier + '\n\n' + "Creating Address-entry on Device:", ip + '\n\n' + "Clearing active session" + '\n\t' + "Session-Id:" + '\t' + s.session_identifier + '\n\t' + "Cluster-Node:" + '\t' + s.re_name + '\n'
            block_src = {'Address': s.in_source_address}
            jinja_data = open("jinjafile.conf", "wb")
            jinja_data.write(JinjaTemplate.render(**block_src))
            jinja_data.close()
            rsp = cu.load( template_path="jinjafile.conf", merge=True )
            clearflow = dev.rpc.clear_flow_session(destination_prefix=s.in_destination_address, source_prefix=s.in_source_address, destination_port=s.in_destination_port, protocol=s.in_session_protocol)
        cu.commit()
        cu.unlock()

        if found == 'f':
            print "No Active Sessions were found with the following criteria:" + '\n\n\t' + "Destination IP-Address:" + '\t' + destip + '\n\t' + "Destination Port:" + '\t' + dport +'\n\t' + "Application:" + '\t\t' + application + '\n'

    except RpcError:
        msg = "{0} was Skipped due to RPC Error.  Device is not a Juniper SRX Series".format(ip.rstrip())
        print msg
        dev.close()

    except Exception as err:
        msg = "{0} was skipped due to unhandled exception.\n{1}".format(ip.rstrip(), err)
        print msg
        traceback.print_exc(file=sys.stdout)

    dev.close()

def runcert(ip):
    process_ip_list.append(ip)
    result = process_device(ip)
    return result

def multiRuncert():
    pool = ThreadPool(cpu_count() * 8)
    global ip_list
    global results
    results = pool.map_async(runcert, ip_list)
    pool.close()
    pool.join()

def runuser(ip):
    process_ip_list.append(ip)
    result = process_device(ip, user=uname, password=upass)
    return result

def multiRunuser():
    pool = ThreadPool(cpu_count() * 8)
    global ip_list
    global results
    results = pool.map_async(runuser, ip_list)
    pool.close()
    pool.join()

def onefn(runner):
    os.system('clear')
    runner()
    remove_jinjafile()
    sys.exit()

def remove_jinjafile():
    os.remove("jinjafile.conf")

if cert:
    onefn(multiRuncert)
    remove_jinjafile()
if uname == '' and upass == '':
    uname = raw_input("\nDevices will require valid login credentials.\nPlease enter your login name: ")
    upass = getpass.getpass(prompt='Please enter your password: ')
    onefn(multiRunuser)
    remove_jinjafile()
if uname != '' and upass == '':
    upass = getpass.getpass(prompt='Please enter your password: ')
    onefn(multiRunuser)
    remove_jinjafile()
if uname != '' and upass != '':
    onefn(multiRunuser)
    remove_jinjafile()
if uname == '' and upass != '':
    uname = raw_input("\nDevices will require valid login credentials.\nPlease enter your login name: ")
    onefn(multiRunuser)
    remove_jinjafile()
else:
    uname = raw_input("\nDevices will require valid login credentials.\nPlease enter your login name: ")
    upass = getpass.getpass(prompt='Please enter your password: ')
    onefn(multiRunuser)
    remove_jinjafile()
