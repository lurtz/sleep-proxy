#!/usr/bin/env python2

import struct


def toInt(packet):
    return struct.unpack('!' + str(len(packet)) + 'B', packet)


def intToBinary(data, base='x'):
    assert base in ['x', 'X', 'b']
    fmt = '{0:' + base + '}'
    return list(map(lambda y: fmt.format(y), data))


def getIPVersion(packet):
    return int(intToBinary([packet[0]])[0][0], 16)


def splitIPHeader(packet):
    version = getIPVersion(packet)
    if version == 4:
        len_bytes = int(intToBinary([packet[0]])[0][1], 16) * 4
        return IPv4(packet[:len_bytes]), packet[len_bytes:]
    elif version == 6:
        return IPv6(packet[:40]), packet[40:]
    else:
        print('no matching IP version found: ' + str(version))
        return None, None


class IPv4:
    def __init__(self, header):
        self.header = header

    @staticmethod
    def createAddress(addrinbytes):
        return '.'.join(map(str, addrinbytes))

    def getSrc(self):
        return IPv4.createAddress(self.header[12:16])

    def getDst(self):
        return IPv4.createAddress(self.header[16:20])

    def __repr__(self):
        return 'IPv4(from ' + self.getSrc() + ' to ' + self.getDst() + ')'


class IPv6:
    def __init__(self, header):
        self.header = header

    @staticmethod
    def createAddress(addrinbytes):
        hexvals = intToBinary(addrinbytes)
        shorts = zip(hexvals[::2], hexvals[1::2])
        return ':'.join(map(lambda x: x[0] + x[1], shorts))

    def getSrc(self):
        return IPv6.createAddress(self.header[8:24])

    def getDst(self):
        return IPv6.createAddress(self.header[24:40])

    def __repr__(self):
        return 'IPv6(from ' + self.getSrc() + ' to ' + self.getDst() + ')'


class TCP:
    @staticmethod
    def splitHeader(packet):
        offset = int(intToBinary([packet[12]])[0][0], 16) * 4
        return TCP(packet[:offset]), packet[offset:]

    def __init__(self, header):
        self.header = header

    def getSrcPort(self):
        return int(''.join(intToBinary(self.header[0:2])), 16)

    def getDstPort(self):
        return int(''.join(intToBinary(self.header[2:4])), 16)


def printSrcAndDst(packet):
    base10 = toInt(packet)
    ip, rest = splitIPHeader(base10)
    if ip is None:
        return
    ipsrc = ip.getSrc()
    ipdst = ip.getDst()
    tcp, rest = TCP.splitHeader(rest)
    print('from ' + ipsrc + ' port ' + str(tcp.getSrcPort()))
    print('to ' + ipdst + ' port ' + str(tcp.getDstPort()))
    print(ip)

if __name__ == '__main__':
    v4packet = 'E\x10\x004\xdcz@\x00@\x06\xda!\xc0\xa8\x01\xc6\xc0\xa8\x01' + \
               '\x01\xbd\xa8\x00\x16S[6/Q\x88\xd4#\x80\x10\x03\x8dw^\x00' + \
               '\x00\x01\x01\x08\n\x03TkhJGQ\xc1'
    v6packet = '\xb4\xd609r\xe8\xcb\x11\x00\x00\x00\x00\xa0\x02\xaa\xaa' + \
               '\xffu\x00\x00\x02\x04\xff\xc4\x04\x02\x08\n\x04\x06X\x9e' + \
               '\x00\x00\x00\x00\x01\x03\x03\x07'  # not an ipv6 packet
    printSrcAndDst(v4packet)
    printSrcAndDst(v6packet)
