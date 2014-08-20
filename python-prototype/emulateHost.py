#!/usr/bin/env python

import socket
import argparse
import subprocess
import struct
import signal
import pcap
from ipparser import splitIPHeader, toInt

'''
What does it need:
    IPv4/IPv6
    multiple IPs
    multiple ports
    restore state on aborts

what needs testing:
    IPv6
'''


def parse_arguments():
    parser = argparse.ArgumentParser(description="emulates a host, which went \
                                     standby and wakes it upon an incoming \
                                     connection")
    parser.add_argument('-i', '--interface', help='interface to listen',
                        default='lo')
    parser.add_argument('-a', '--address', help='ips on which shall be \
                        listened to in cidr notation',
                        default='10.0.0.1/16,fe80::123/64')
    parser.add_argument('-p', '--ports', help='comma seperated list of ports \
                        to listen on', default="12345,23456")
    parser.add_argument('-m', '--macaddress', help='mac of the host to \
                         wake', default='01:12:34:45:67:89')
    return parser.parse_args()


def changeIPAddr(iface, ip, action='add'):
    assert action == 'add' or action == 'del'
    cmd = ['ip', 'addr', action, ip, 'dev', iface]
    print(cmd)
    subprocess.call(cmd)


def getPureIP(ip):
    wosubnet = ip.split('/')[0]
    woiface = wosubnet.split('%')[0]
    return woiface


def getAF(ip):
    try:
        socket.inet_pton(socket.AF_INET, getPureIP(ip))
        return socket.AF_INET
    except socket.error:
        socket.inet_pton(socket.AF_INET6, getPureIP(ip))
        return socket.AF_INET6


def getIptablesCmd(ip):
    return 'iptables' if getAF(ip) == socket.AF_INET else 'ip6tables'


def changeDropRST(ip, method='A'):
    assert method in ['A', 'I', 'D']
    cmd = [getIptablesCmd(ip), '-' + method, 'OUTPUT', '-s', getPureIP(ip),
           '-p', 'tcp', '--tcp-flags', 'ALL', 'RST,ACK', '-j', 'DROP']
    print(cmd)
    subprocess.call(cmd)


def changeOpenPorts(ip, ports, method):
    assert method in ['A', 'D', 'I']
    iptcmd = getIptablesCmd(ip)
    pip = getPureIP(ip)
    cmds = []
    for port in ports:
        cmds += [[iptcmd, '-' + method, 'INPUT', '-d', pip,
                 '-p', 'tcp', '--syn',
                 '--dport', str(port), '-j', 'ACCEPT']]
    cmds += [[iptcmd, '-' + method, 'INPUT', '-d', pip,
             '-p', 'tcp', '-j', 'REJECT']]
    cmds += [[iptcmd, '-' + method, 'INPUT', '-d', pip,
             '-p', 'udp', '-j', 'REJECT']]
    if method == 'I':
        cmds = reversed(cmds)
    for cmd in cmds:
        print(cmd)
        subprocess.call(cmd)


def addIPAddr(iface, ip, ports):
    changeOpenPorts(ip, ports, 'I')
    changeDropRST(ip, 'I')
    changeIPAddr(iface, ip, 'add')


def delIPAddr(iface, ip, ports):
    changeIPAddr(iface, ip, 'del')
    changeDropRST(ip, 'D')
    changeOpenPorts(ip, ports, 'D')


def addIPAddrs(iface, ips, ports):
    for ip in ips:
        addIPAddr(iface, ip, ports)


def delIPAddrs(iface, ips, ports):
    for ip in ips:
        delIPAddr(iface, ip, ports)


def getBindableIP(iface, ip):
    if ip.startswith('fe80'):
        return getPureIP(ip) + '%' + iface
    else:
        return getPureIP(ip)


def waitAndListen(iface, ips, ports):
    #  it would be nice to drop firewall rules and test against tcpflags, but
    #  this does not work with ipv6 because of a bug in pcap
    #  bpf = 'tcp and tcp[tcpflags] & tcp-syn != 0'
    bpf = 'tcp'
    bpf += ' and dst host (' + ' or '.join(map(getPureIP, ips)) + ')'
    bpf += ' and dst port (' + ' or '.join(map(str, ports)) + ')'
    print('Listening with filter: ' + bpf)
    pc = pcap.pcap(iface)
    pc.setfilter(bpf)
    for ts, pkt in pc:
        break
    return pkt, splitIPHeader(toInt(pkt)[14:])[0].getSrc()


def wol(macaddress):
    """ Switches on remote computers using WOL. """

    print('waking ' + macaddress)
    # Check macaddress format and try to compensate.
    if len(macaddress) == 12:
        pass
    elif len(macaddress) == 12 + 5:
        sep = macaddress[2]
        macaddress = macaddress.replace(sep, '')
    else:
        raise ValueError('Incorrect MAC address format')

    # Pad the synchronization stream.
    data = ''.join(['FFFFFFFFFFFF', macaddress * 20])
    send_data = ''

    # Split up the hex values and pack.
    for i in range(0, len(data), 2):
        send_data = ''.join([send_data,
                             struct.pack('B', int(data[i: i + 2], 16))])

    # Broadcast it to the LAN.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(send_data, ('<broadcast>', 7))


def getPingCMD(ip):
    return 'ping6' if getAF(ip) == socket.AF_INET6 else 'ping'


def pingAndWait(iface, ip, tries=2):
    ipcmd = getPingCMD(ip)
    cmd = [ipcmd, '-c', str(1), getBindableIP(iface, ip)]
    print(cmd)
    for i in range(tries):
        retval = subprocess.call(cmd)
        if retval == 0:
            return


def changeBlockICMP(dst, method):
    assert method in ['A', 'I', 'D']
    # iptables -A INPUT -i eth0 -p icmp --icmp-type destination-unreachable
    # -j ACCEPT
    icmpv = 'icmpv6' if getAF(dst) == socket.AF_INET6 else 'icmp'
    cmd = [getIptablesCmd(dst), '-' + method, 'OUTPUT', '-d', dst, '-p',
           icmpv, '--' + icmpv + '-type', 'destination-unreachable', '-j',
           'DROP']
    print(cmd)
    subprocess.call(cmd)


def method1(iface, ips, ports, hwaddr):
    ''' Listen for incoming SYN packets and wake the host defined with hwaddr.\
        because multiple SYN packets are sent from the client reinserting the \
        SYN packet is not necessary, but may lower the latency '''
    # actually listens on the given ip but on all ports, not this specific one
    # should be solveable with iptables
    # this also implies that one invocation listens on all ports of a sleeping
    # server
    addIPAddrs(iface, ips, ports)
    # data is the ip packet without ethernet headers
    try:
        data_address = waitAndListen(iface, ips, ports)
    except (KeyboardInterrupt, Exception) as e:
        print('error during listening for incoming packets')
        print(e)
        delIPAddrs(iface, ips, ports)
        return
    print('got something')
    try:
        # add iptables rule to block ICMP messages to address, that ip is not
        # there
        changeBlockICMP(data_address[1], 'I')
    except Exception as e:
        print('unable to block icmp messages')
        print(e)
        delIPAddrs(iface, ips, ports)
        return
    delIPAddrs(iface, ips, ports)
    try:
        wol(hwaddr)
        pingAndWait(iface, ips[0])
    except Exception as e:
        print(e)
    # delete iptables rule
    changeBlockICMP(data_address[1], 'D')


def parsePorts(ports):
    return list(map(int, ports.split(',')))


class IPFormatException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def sanitizeIP(ip):
    if ip.find('/') != ip.rfind('/'):
        raise IPFormatException('Too many / in IP')
    version = getAF(ip)
    if ip == getPureIP(ip):
        if version == socket.AF_INET6:
            postfix = '/64' if ip != '::1' else '/128'
        else:
            postfix = '/24'
        ip = ip + postfix
    postfix = int(ip.split('/')[1])
    maxprefixlen = 128 if version == socket.AF_INET6 else 32
    if postfix < 0 or postfix > maxprefixlen:
        raise IPFormatException('Invalid netmask')
    return ip


def sanitizeIPs(addresses):
    return list(map(sanitizeIP, addresses))


def signalHandler(x, y):
    pass


def emulateHost(iface, ips, ports, mac):
    try:
        method1(iface, ips, ports, mac)
    except Exception as e:
        print('something went wrong')
        print(e)
        delIPAddrs(iface, ips, ports)

if __name__ == '__main__':
    args = parse_arguments()
    print(args)
    ports = parsePorts(args.ports)
    ips = sanitizeIPs(args.address.split(','))
    signal.signal(signal.SIGTERM, signalHandler)
    signal.signal(signal.SIGINT, signalHandler)
    emulateHost(args.interface, ips, ports, args.macaddress)
