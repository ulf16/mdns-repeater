CHANGELOG
=========
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

