mdns-repeater
==============

mdns-repeater is a Multicast DNS repeater for Linux. Multicast DNS uses the 
224.0.0.251 address, which is "administratively scoped" and does not 
leave the subnet.

This program rebroadcasts mDNS packets from one interface to other interfaces.
It was designed to enable zeroconf devices to work properly across different
subnets or network segments.

Since the mDNS protocol sends the AA records in the packet itself, the 
repeater does not need to forge the source address. Instead, the source 
address is of the interface that repeats the packet.

Introduction
------------
mdns-repeater provides seamless reflection of mDNS traffic between multiple network interfaces, enabling discovery of services across subnets or network segments. Key features include:

- Reflection of both IPv4 and IPv6 mDNS packets.
- Support for legacy unicast reply forwarding to aid Bonjour and Time Capsule device resolution.
- Compatibility with systemd foreground service operation.
- Coexistence with Avahi daemon through use of `SO_REUSEADDR` and `SO_REUSEPORT` socket options.

Typical Use Cases
-----------------
- Wi‑Fi ↔ Ethernet networks on laptops, access points, or routers.
- Docker containers communicating with the host or other containers.
- VPN connections (WireGuard, Tailscale, OpenVPN, etc.) bridging remote networks.

When connecting remote networks via VPN, mDNS reflection enables cross-site service discovery, allowing devices on separate sites to find each other through multicast DNS.

USAGE
-----
mdns-repeater only requires the interface names and it will do the rest.
For example, if your wireless network interface is named `lan0` and your VPN interface is `vpn0`, you would run:

    mdns-repeater lan0 vpn0

You can also specify the `-f` flag for debugging, which prints packets as they 
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
`mdns-repeater` repeats packets **between the interfaces you specify**, so you must pick the correct pair(s) for your system. Typical cases:

- Home router or SBC:
  - `mdns-repeater lan0 eth0`
  - `mdns-repeater lan0 vpn0` (LAN ↔ VPN)
- Dual‑NIC host bridging two LANs:
  - `mdns-repeater eth0 eth1`
- Wi‑Fi ↔ Ethernet on a laptop or access point:
  - `mdns-repeater wlan0 eth0`

> Tip: list your interfaces with `ip -br link` and find their IPs with `ip -br addr`.

Examples
--------
**Two interfaces** (most common):

```
mdns-repeater <LAN-IFACE> <OTHER-IFACE>
# e.g.
mdns-repeater lan0 vpn0
```

**Three or more interfaces** (fully meshed):

```
mdns-repeater lan0 eth1 vpn0
```
All packets received on one interface are re‑sent on the others. Order does not matter.

Systemd Service (interface-specific)
------------------------------------
For a persistent setup, create a unit that specifies the exact interfaces on your machine. Replace the interface names accordingly:

```
[Unit]
Description=mDNS repeater service for specified interfaces
After=network-online.target
Requires=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/mdns-repeater -q -f <iface1> <iface2> [<iface3> ...]
Restart=always
RestartSec=2
KillSignal=SIGINT
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
```

For example, to reflect between a LAN and a VPN interface, set `ExecStart=... mdns-repeater -q -f lan0 vpn0`.

Firewall Considerations
-----------------------
Ensure that UDP port 5353 is allowed on all interfaces participating in mDNS reflection. This is necessary for the multicast DNS packets to be received and forwarded properly.

Docker/Avahi notes
------------------
- Only one Avahi instance should bind UDP/5353 on the host. If containers run Avahi, either disable it inside the container or avoid `--network=host`.
- You can restrict host Avahi to specific interfaces in `/etc/avahi/avahi-daemon.conf`:

```
[server]
allow-interfaces=lan0,vpn0
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
4. If you see `send(): Required key not available` over VPN:
   - Ensure the VPN peer’s AllowedIPs include multicast ranges: `224.0.0.0/4` (IPv4) and `ff00::/8` (IPv6).
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
