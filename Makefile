# Makefile for mdns-repeater (modernized)
# Compatible with old layout; adds install/uninstall and DESTDIR/PREFIX support.

# ====== configuration ======
CC       ?= cc
PREFIX   ?= /usr/local
SBIN     ?= $(PREFIX)/sbin
UNITDIR  ?= $(PREFIX)/lib/systemd/system
ZIP_NAME  = mdns-repeater-$(HGVERSION)
ZIP_FILES = mdns-repeater \
            README.txt \
            LICENSE.txt

# Try to get a nice version string from git; fall back to short SHA
HGVERSION := $(shell (git describe --always --dirty --broken 2>/dev/null) || git rev-parse --short HEAD 2>/dev/null || echo unknown)

# Build flags
CPPFLAGS ?= -D_GNU_SOURCE -D_DEFAULT_SOURCE -DHGVERSION=\"$(HGVERSION)\"
CFLAGS   ?= -O2 -Wall
LDFLAGS  ?=
LDLIBS   ?=

# Debug override
ifdef DEBUG
  CFLAGS := -O0 -g -Wall
endif

# ====== targets ======
.PHONY: all clean zip install uninstall

all: mdns-repeater

# Rebuild when version changes (kept for compatibility with original)
mdns-repeater.o: _hgversion

# Rely on implicit rules for .c -> .o and link, or add explicit link rule if needed
mdns-repeater: mdns-repeater.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Package
zip: TMPDIR := $(shell mktemp -d)
zip: mdns-repeater
	mkdir -p $(TMPDIR)/$(ZIP_NAME)
	cp -t $(TMPDIR)/$(ZIP_NAME) $(ZIP_FILES) 2>/dev/null || true
	-$(RM) $(CURDIR)/$(ZIP_NAME).zip
	cd $(TMPDIR) && zip -r $(CURDIR)/$(ZIP_NAME).zip $(ZIP_NAME)
	-$(RM) -rf $(TMPDIR)

# Version stamp file (compat name retained)
.PHONY: dummy
_hgversion: dummy
	@echo $(HGVERSION) | cmp -s $@ - || echo $(HGVERSION) > $@

# Install/uninstall
install: mdns-repeater
	install -d $(DESTDIR)$(SBIN)
	install -m 0755 mdns-repeater $(DESTDIR)$(SBIN)/mdns-repeater
	# Optional: install unit file if present at ./systemd/mdns-repeater.service
	@if [ -f systemd/mdns-repeater.service ]; then \
		install -d $(DESTDIR)$(UNITDIR); \
		install -m 0644 systemd/mdns-repeater.service $(DESTDIR)$(UNITDIR)/mdns-repeater.service; \
		echo "Installed systemd unit to $(DESTDIR)$(UNITDIR)/mdns-repeater.service"; \
	else \
		echo "(No systemd unit file found at systemd/mdns-repeater.service — skipped)"; \
	fi

uninstall:
	-$(RM) $(DESTDIR)$(SBIN)/mdns-repeater
	-$(RM) $(DESTDIR)$(UNITDIR)/mdns-repeater.service

clean:
	-$(RM) *.o
	-$(RM) _hgversion
	-$(RM) mdns-repeater
	-$(RM) mdns-repeater-*.zip
