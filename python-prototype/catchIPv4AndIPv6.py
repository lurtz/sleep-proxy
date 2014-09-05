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

import argparse
import ipparser
import emulateHost


def parse_arguments():
    parser = argparse.ArgumentParser(description="test if raw IPv4 and IPv6 \
                                     packets contain their IP header, if \
                                     capturing is restricted to TCP")
    parser.add_argument('-i', '--interface', help='interface to listen',
                        default='lo')
    parser.add_argument('-4', '--v4address', help='ipv4 on which shall be \
                        listened to', default='127.0.0.1')
    parser.add_argument('-6', '--v6address', help='ipv6 on which shall be \
                        listened to', default='::1')
    return parser.parse_args()


def listenOnSocket(iface, address):
    socket = emulateHost.getRAWSocket(iface, address)
    data_address = socket.recvfrom(65000)
    ipparser.printSrcAndDst(data_address[0])
    socket.close()


if __name__ == '__main__':
    args = parse_arguments()
    print('IPv4:')
    listenOnSocket(args.interface, args.v4address)
    print('IPv6:')
    listenOnSocket(args.interface, args.v6address)
    pass
