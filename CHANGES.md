CHANGELOG
=========

Version 1.3.0 (2025-11-12)
---------------------------
This release focuses on performance, reliability, and code quality improvements for modern multicast environments.

### Key Developments
- **Performance optimizations**: Reduced CPU usage under high multicast load.
- **IPv6 safety improvements**: Prevents feedback loops and excessive rebroadcast bursts.
- **Firewall interoperability**: Improved behavior with nftables and systemd-networkd.
- **Graceful handling of link-local addressing**: Better support for tunnels (e.g., WireGuard, Tailscale).
- **Code deduplication and refactor**: Simplified multicast forwarding paths.
- Minor **logging refinements** and cleanup.

Version 1.2.0 (2025-11-09)
---------------------------
This release completes full cross-LAN Bonjour (mDNS) interoperability across WireGuard by adding IPv6 reflection and correct legacy-unicast forwarding.

### New Features
- **IPv6 mDNS reflection**: joins `ff02::fb` per interface and mirrors IPv6 multicast queries and responses.
- **Legacy unicast support**: forwards replies to the original source port (not always 5353), fixing Time Capsule and macOS resolve stalls.
- **Systemd integration polish**: supports `Type=simple`, foreground operation (`-f`), and graceful shutdown with SIGINT.
- **Improved coexistence with Avahi** via `SO_REUSEADDR`/`SO_REUSEPORT`.
- **Foreground logging** improvements (`-q`, `-v`, `-S`).

### Fixes & Improvements
- Correct handling of `IP_PKTINFO` to differentiate multicast vs unicast.
- Dropped obsolete IPv4-only assumptions.
- Ensures unicast replies cross a WireGuard link instead of being rewritten to multicast.
- Better resilience under systemd (no double-bind or zombie processes).
- Improved Makefile and safer build flags.

### Notes
- Tested successfully between Armbian ARM64 ↔ Armbian ARM using WireGuard 10.99.99.0/30.
- Tag: **v1.2.0**, branch: `systemd-friendly`, merged into master for this release.

Version 1.1.0 (2025-11-07)
---------------------------
This release modernizes **mdns-repeater** for current Linux systems and systemd environments while preserving backward compatibility.

### New Features
- Default **foreground mode** (`-f` no longer required). New `-d` flag to daemonize.
- Added **verbosity controls**:
  - `-q` (quiet, errors only)
  - `-v` (verbose, per-packet)
  - `-S` (log to stderr instead of syslog)
- Logs now go to **syslog** by default (safer under systemd).
- Added **SO_REUSEPORT** for better coexistence with Avahi.
- **Modern Makefile** with `install`, `uninstall`, `DESTDIR` and `PREFIX` support.
- Added **README sections** for interface selection, systemd usage, Docker/Avahi interaction, and troubleshooting.
- Compatible with **WireGuard cross-LAN setups** out of the box.

### Improvements
- Updated help output and argument parsing with `getopt_long()`.
- Proper PID file handling and runtime safety checks.
- Removed unnecessary backgrounding when under systemd.
- Improved logging and signal handling (SIGINT/SIGTERM cleanup).

### Notes
- Tested on Debian Bookworm / Ubuntu 24.04 / Armbian 6.x kernels.
- Backward compatible with the original 2011 build when compiled with `-DLEGACY=1`.
- Version tagged as **1.1.0**; base version was 1.0.0 (2011).

