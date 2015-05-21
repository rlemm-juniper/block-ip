#!/usr/bin/python

import argparse
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import cpu_count
import os
import sys
import getpass
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.factory import loadyaml
from jnpr.junos.exception import RpcError

globals().update( loadyaml('flowsession.yml'))

results = ''
test = []
cert = ''
onedevice = ''
destip = ''
uname = ''
upass = ''
dport = ''
application = ''

parser = argparse.ArgumentParser(add_help=True)

parser.add_argument("-d", action="store",
                    help="Specify Device")

parser.add_argument("-i", action="store",
                    help="Destination IP-Address")

parser.add_argument("-a", action="store",
                    help="Application - Acceptable Values: ah, egp, esp, gre, icmp, icmp6,igmp, ipip, ospf, pim, rsvp, sctp, tcp, udp")

parser.add_argument("-u", action="store",
                    help="Login with username")

parser.add_argument("-p", action="store",
                    help="Destination Port")

parser.add_argument("-c", action="store_false",
                    help="Login with Device Certificate")

parser.add_argument("-pw", action="store_false",
                    help="Login with password")

args = parser.parse_args()

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
if args.u:
    uname = args.u
if args.p:
    dport = args.p
if args.pw:
    upass = args.pw

def process_device(ip, **kwargs):
    dev = Device(host=ip, **kwargs)
    cu = Config(dev)
    print "Searching for active sessions matching Destination IP-Address:", destip, ", Destination-Port:", dport, ", Application:", application

    try:

        dev.open()
        session_table = SessionTable(dev)
        session_table.get()

        for s in session_table:
          if session_table.keys():
            if s.session_direction == 'In' and s.destination_address == destip and s.destination_port == dport and s.session_protocol == application:
              print "Found Session matching Source-Address:", s.source_address
              print "Creating Address-entry and clearing active session"
              block_src = {'Address': s.source_address}
              rsp = cu.load( template_path="add-global-address-book-template.conf", template_vars=block_src )
#              clearflow = dev.rpc.clear_flow_session(destination_prefix=s.destination_address, source_prefix=s.source_address, destination_port=s.destination_port, protocol=s.session_protocol)
#              cu.commit()

        if destination_address != destip and destination_port != dport and session_protocol != application:
          print "No Active Sessions were found with the following criteria:"
          print ""
          print "Destination IP-Address:", destip
          print "Destination-Port:", dport
          print "Application:", application

    except RpcError:
        msg = "{0} was Skipped due to RPC Error.  Device is not EX/Branch-SRX Series".format(ip.rstrip())
        alldatafile.write(msg + '\n')
        print msg
        dev.close()

    except Exception as err:
        msg = "{0} was skipped due to unhandled exception.\n{1}".format(ip.rstrip(), err)
        alldatafile.write(msg + '\n')
        print msg
        traceback.print_exc(file=sys.stdout)

    dev.close()

def runcert(ip):
    test.append(ip)
    result = process_device(ip)
    return result

def multiRuncert():
    pool = ThreadPool(cpu_count() * 16)
    global ip_list
    global results
    results = pool.map_async(runcert, ip_list)
    pool.close()
    pool.join()

def runuser(ip):
    test.append(ip)
    result = process_device(ip, user=uname, password=upass)
    return result

def multiRunuser():
    pool = ThreadPool(cpu_count() * 16)
    global ip_list
    global results
    results = pool.map_async(runuser, ip_list)
    pool.close()
    pool.join()

def onefn(runner):
    os.system('clear')
    runner()
    sys.exit()

if cert:
    onefn(multiRuncert)
if uname == '':
    uname = raw_input("\nDevices will require valid login credentials.\nPlease enter your login name: ")
if upass == '':
    upass = getpass.getpass(prompt='Please enter your password: ')
    onefn(multiRunuser)
else:
    onefn(multiRunuser)
