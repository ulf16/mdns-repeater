mdns-repeater
==============
mdns-repeater is a Multicast DNS repeater for Linux. Multicast DNS uses the 
224.0.0.251 address, which is "administratively scoped" and does not 
leave the subnet.

This program re-broadcast mDNS packets from one interface to other interfaces.
It was written primarily to be run on my Linksys WRT54G which runs dd-wrt,
since my wireless network is on a different subnet from my wired network and 
I would like my zeroconf devices to work properly across the two subnets.

Since the mDNS protocol sends the AA records in the packet itself, the 
repeater does not need to forge the source address. Instead, the source 
address is of the interface that repeats the packet.


Introduction
------------
mdns-repeater provides seamless reflection of mDNS traffic between multiple network interfaces, enabling discovery of services across subnets. Key features include:

- Reflection of both IPv4 and IPv6 mDNS packets.
- Support for legacy unicast reply forwarding to aid Bonjour and Time Capsule device resolution.
- Compatibility with systemd foreground service operation.
- Coexistence with Avahi daemon through use of `SO_REUSEADDR` and `SO_REUSEPORT` socket options.


USAGE
-----
mdns-repeater only requires the interface names and it will do the rest.
For example, the dd-wrt standard installation defines br0 for the wireless 
interface and vlan1 as the WAN interface, I would use:

    mdns-repeater br0 vlan1

You can also specify the -f flag for debugging, which prints packets as they 
are received.


Build & Install
---------------
To build the program, run:

    make

To install the binary system-wide, run:

    sudo make install

Verify the installed version with:

    mdns-repeater -v


Choosing Interfaces
-------------------
`mdns-repeater` repeats packets **between the interfaces you name**, so you must pick the correct pair(s) for your system. Typical cases:

- Home router or SBC:
  - `mdns-repeater br0 eth0`
  - `mdns-repeater end0 wg0` (LAN ↔ WireGuard)
- Dual‑NIC host bridging two LANs:
  - `mdns-repeater eth0 eth1`
- Wi‑Fi ↔ Ethernet on a laptop/AP:
  - `mdns-repeater wlan0 eth0`

> Tip: list your interfaces with `ip -br link` and find their IPs with `ip -br addr`.

Examples
--------
**Two interfaces** (most common):

```
mdns-repeater <LAN-IFACE> <TUNNEL-IFACE>
# e.g.
mdns-repeater end0 wg0
```

**Three or more interfaces** (fully meshed):

```
mdns-repeater br0 eth1 wg0
```
All packets received on one interface are re‑sent on the others. Order does not matter.

Systemd Service (interface-specific)
------------------------------------
For a persistent setup, create a unit that pins the exact interfaces on **that** machine. Replace the names to match your host:

```
[Unit]
Description=mDNS repeater (LAN↔WG)
After=network-online.target wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/mdns-repeater -q -f end0 wg0
Restart=always
RestartSec=2
KillSignal=SIGINT
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
```

If your LAN interface is different (e.g., `enx001e063263da`), change the `ExecStart` line accordingly. For multiple LANs, name all of them: `ExecStart=... mdns-repeater -q -f lan0 lan1 wg0`.

Docker/Avahi notes
------------------
- Only one Avahi instance should bind UDP/5353 on the host. If containers run Avahi, either disable it inside the container or avoid `--network=host`.
- You can restrict host Avahi to specific interfaces in `/etc/avahi/avahi-daemon.conf`:

```
[server]
allow-interfaces=end0,wg0
deny-interfaces=docker0,veth*,br*
```

Verification & Troubleshooting
------------------------------
1. See service status:
   - `systemctl status mdns-repeater`
2. Watch traffic:
   - `sudo tcpdump -ni <iface> udp port 5353`
3. List services across subnets:
   - `avahi-browse -rt _ipp._tcp`
4. If you see `send(): Required key not available` over WireGuard:
   - Ensure the WG peer’s `AllowedIPs` include multicast ranges: `224.0.0.0/4` (IPv4) and `ff00::/8` (IPv6).
5. If the service starts/stops rapidly under systemd, use foreground mode (`-f`) in the unit, or set `Type=forking` if you prefer daemon mode.

Security & Scope
----------------
This tool only repeats mDNS (UDP/5353). It does not forward arbitrary traffic. Pair it with proper routing between subnets for unicast replies (or use your routers’ site‑to‑site link) so discovery completes end‑to‑end.

Version
-------
Current release: v1.2.0

Changelog highlights:
- Added IPv6 mDNS reflection support.
- Improved legacy unicast reply forwarding for better Bonjour compatibility.
- Enhanced systemd foreground service integration.
- Improved coexistence with Avahi via socket option adjustments.

LICENSE
--------
Copyright (C) 2011 Darell Tan

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
