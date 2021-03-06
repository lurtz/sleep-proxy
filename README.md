INFO
====

Keeps the illusion, that a host is powered on and available while it is powered
off or in standby. A small device, e.g. an OpenWrt router, using this programm
can wake this host using WOL upon an incoming connection.

BUILDING
========

To compile you need cmake and pcap installed. Your compiler should understand
C++11.

To build install pcap with its development files and run:

    mkdir build
    cd build
    meson ..
    ninja

BUILDING ON OPENWRT
===================

Setup the OpenWrt SDK as described at
[Using the SDK](https://openwrt.org/docs/guide-developer/using_the_sdk).

Make sure all openwrt build dependencies are met an run:

    mkdir $OPENWRT_SDK/packages/sleep-proxy
    cp -r $SLEEP_PROXY_ROOT/openwrt-cmake/* $OPENWRT_SDK/packages/sleep-proxy
    cd $OPENWRT_SDK

    # configure your target router, make sure Network/sleep-proxy is selected
    make menuconfig
    make

You will get your package from bin/*/packages.

EXECUTING
=========

At runtime the commands ping, ping6, ip, iptables and ip6tables should be
available.

After building you find in build/src the binaries watchHost,
emulateHost, waker and sniffer. If you do not try to debug only watchHost is
of interest for you.

An example configuration watchHost.conf is available in the directory config,
with everything commented out. Please read watchHost -h and the comments in
watchHost.conf.

When running watchHost it will add ip addresses and firewall rules to your
machine in order to fake another machine running. At the moment it cannot
manipulate DNS or DHCP, so this has to be setup statically before. Just tell
your DHCP server to offer the emulated host always the same IP. Your DNS
server should always respond with the same ip, when asked about the emulated
host.

watchHost will run in the foreground and terminate upon SIGTERM and SIGINT
gracefully and clean all ips and firewall rules it created.

EXAMPLES
========

The following will fake the ip 192.168.1.123 and fe80::123 with ports 22 and
80 open. Upon an incoming connection the machine with mac aa:bb:cc:dd:ee:ff
will be started:

    watchHost -i eth0 -a 192.168.1.123,fe80::123 -p 22,80 -m aa:bb:cc:dd:ee:ff

This will take the configuration given in watchHost.conf and print messages to
syslog. This mode is intended to be used by init daemons.

    watchHost -c watchHost.conf --syslog

BUGS
====

IPv4 is well tested, IPv6 is much less tested. Besides that the IPv6
implementation cannot handle reboots of the emulated machine. The
emulated machine will test the network for duplicated addresses and see that
its desired address is already taken and stay in the tentative state.

Another problem is bloat. Sure you can blame for using C++ and exceptions, but
this huge bloat was not expected. This app consumes with dependencies about
1MB of disc space, where libstdc++ is most of it. At runtime it takes 8MB,
which is doable by most recent routers, but much more than expected.
