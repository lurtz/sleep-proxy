#!/usr/bin/env python

# Copyright (C) 2014  Lutz Reinhardt
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import signal
import argparse
import socket
import subprocess
from emulateHost import getPingCMD, getBindableIP, parsePorts, sanitizeIPs
from emulateHost import emulateHost, getPureIP
import threading
import shutil
import time

'''
Watch a host given by ip or hostname and execute emulateHost if this host goes
off with a given list of ports.

If a hostname is given try to get its ipv4 and ipv6 addresses and call
emulateHost. If only an IP is given, don't try to get further information.
If a hostname is given /etc/hosts may have to be modified as well.

If more than one IP is given prefer IPv6 addresses for checking if the host is
alive.
'''


def getMAC(ip):
    # use 'ip neigh show' to get ips and macs
    ip = getPureIP(ip)
    cmd = ['ip', 'neigh', 'show']
    arp = subprocess.check_output(cmd).decode('ascii').split('\n')
    fields = [x.split(' ') for x in arp[:-1]]
    hits = list(filter(lambda x: x[0] == ip, fields))
    return hits[0][4] if hits and hits[0][4] != 'FAILED' else None


class PingThread:
    def __init__(self, iface, target):
        self.iface = iface
        self.target = target
        self.targetResponse = False

    def __call__(self):
        cmd = [getPingCMD(self.target), '-c', '1',
               getBindableIP(self.iface, self.target)]
        self.targetResponse = subprocess.call(cmd) == 0


def pingIPs(iface, ips):
    pingTargets = [PingThread(iface, ip) for ip in ips]
    threads = [threading.Thread(target=t) for t in pingTargets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    isAlive = False
    for t in pingTargets:
        isAlive = isAlive or t.targetResponse
    return isAlive


def getIPs(hostname):
    addr = socket.getaddrinfo(hostname, None)
    return frozenset([ip[4][0] for ip in addr])


def getHostsLine(hostname, ip):
    return ip + '\t' + hostname + '\n'


def getLengthOfTextFile(f):
    oldpos = f.tell()
    for line in f:
        pass
    length = f.tell()
    f.seek(oldpos)
    return length


def addHostToHosts(hostname, ips):
    shutil.copy2('/etc/hosts', '/tmp/tmphosts')
    with open('/tmp/tmphosts', 'r') as hosts:
        hosts.seek(getLengthOfTextFile(hosts))
        for ip in map(getPureIP, ips):
            hosts.write(getHostsLine(hostname, ip))
    shutil.copy2('/tmp/tmphosts', '/etc/hosts')


def delHostFromHosts(hostname, ips):
    with open('/etc/hosts', 'r') as hosts:
        with open('/tmp/tmphosts', 'w') as tmphosts:
            for line in hosts:
                lineIsFromHost = False
                for ip in ips:
                    lineIsFromHost = lineIsFromHost or\
                        line == getHostsLine(hostname, ip)
                if not lineIsFromHost:
                    tmphosts.write(line)
    shutil.move('/tmp/tmphosts', '/etc/hosts')


class SignalHandler:
    def __init__(self):
        self.loop = True

    def __call__(self, x, y):
        self.loop = False

    def __bool__(self):
        return self.loop

    def __nonzero__(self):
        return self.__bool__()


def get_arguments():
    parser = argparse.ArgumentParser(
        description="watches a given host by hostname or IPv4/IPv6 address. If\
        the host goes into standby, it is going to be emulated by listening on\
        the given ports. If a SYN packet comes in into any of these ports, the\
        hosts will be waked up. When the host goes into standby after a while\
        again, it will be emulated again.")
    parser.add_argument('-n', '--hostname', help='hostname to watch')
    parser.add_argument('-a', '--address', help='ips on which shall be \
                        listened to in cidr notation')
    parser.add_argument('-p', '--ports', help='comma seperated list of ports \
                        to listen on', default="12345,23456")
    parser.add_argument('-m', '--macaddress', help='mac of the host to \
                         wake')
    parser.add_argument('-i', '--iface', help='which interface shall be used \
                        to watch the host on', default='lo')
    return parser.parse_args()

if __name__ == '__main__':
    args = get_arguments()
    print(args)
    signalHandler = SignalHandler()
    signal.signal(signal.SIGTERM, signalHandler)
    signal.signal(signal.SIGINT, signalHandler)
    if args.address:
        ips = args.address.split(',')
    else:
        ips = getIPs(args.hostname)
    ips = sanitizeIPs(ips)
    ports = parsePorts(args.ports)
    macs = list(frozenset([getMAC(ip) for ip in ips]))
    mac = macs[0] if not args.macaddress else args.macaddress
    while signalHandler:
        print('main')
        while pingIPs(args.iface, ips) and signalHandler:
            time.sleep(0.5)
            print('pinging hostname ' + args.hostname + ' with ips ' +
                  str(ips) + ' and macs ' + str(macs))
        if signalHandler:
            emulateHost(args.iface, ips, ports, mac)
