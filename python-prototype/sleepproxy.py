#!/usr/bin/env python2

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

import avahi
import dbus
import gobject
from dbus.mainloop.glib import DBusGMainLoop
import socket
import signal
import dns.message

# TODO detect avahi restarts and reconnect


class ZeroconfService:
    """A simple class to publish a network service with zeroconf using
    avahi.
    """

    def __init__(self, name, port, stype="_http._tcp",
                 domain="", host="", text=""):
        self.name = name
        self.stype = stype
        self.domain = domain
        self.host = host
        self.port = port
        self.text = text
        self.bus = dbus.SystemBus()
        self.server = dbus.Interface(
            self.bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER),
            avahi.DBUS_INTERFACE_SERVER)
        self.server.connect_to_signal("StateChanged", self.stateChangedHandler)
        self.stateChangedHandler(self.server.GetState(), 'Call from init')

    def stateChangedHandler(self, state, error):
        print(str(state) + ": " + str(error))
        if state.real == avahi.SERVER_RUNNING:
            self.publish()
        elif state.real == avahi.SERVER_COLLISION or avahi.SERVER_REGISTERING:
            self.unpublish()

    def publish(self):
        print('Publishing')
        try:
            self.group
        except:
            pass
        else:
            return
        g = dbus.Interface(
            self.bus.get_object(avahi.DBUS_NAME, self.server.EntryGroupNew()),
            avahi.DBUS_INTERFACE_ENTRY_GROUP)

        index = 0
        name = self.name
        while True:
            try:
                g.AddService(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC,
                             dbus.UInt32(0), name, self.stype,
                             self.domain, self.host, dbus.UInt16(self.port),
                             avahi.string_array_to_txt_array(self.text))
            except Exception as e:
                print(e)
                index += 1
                name = '%s #%s' % (self.name, str(index))
            else:
                break
        g.Commit()
        self.group = g
        self.group.connect_to_signal("StateChanged",
                                     self.entryGroupStateHandler)

    def entryGroupStateHandler(self, state, error):
        print(str(state) + ": " + str(error))
        if state == avahi.ENTRY_GROUP_COLLISION:
            self.unpublish()
            self.publish()

    def unpublish(self):
        try:
            print('Unpublishing')
            self.group.Reset()
            del self.group
        except:
            pass


def listen(socket, condition):
    print('Network activity')
    data, address = socket.recvfrom(2048)
    print(address)
#    f = open('message', 'w')
#    f.write(data)
#    f.close()
    try:
        message = dns.message.from_wire(data)
        print(message)
    except Exception as e:
        print(e)
        pass
    return True


if __name__ == "__main__":
    DBusGMainLoop(set_as_default=True)
    port = 3000
    sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock6.bind(('', port))
    loop = gobject.MainLoop()
    gobject.io_add_watch(sock6, gobject.IO_IN, listen)
    service = ZeroconfService(name="SleepProxy", port=3000,
                              stype='_sleep-proxy._udp')
    signalhandler = lambda x, y: loop.quit()
    signal.signal(signal.SIGTERM, signalhandler)
    signal.signal(signal.SIGINT, signalhandler)
    loop.run()
    service.unpublish()
    sock6.close()
