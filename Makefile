# SMTP Connection Monitor - Makefile
# https://github.com/managedserver/smtp-monitor
#
# Usage:
#   make              Build smtp-monitor
#   make install      Install to /usr/local/bin (requires root)
#   make uninstall    Remove from /usr/local/bin
#   make clean        Remove build artifacts

CC       ?= gcc
CFLAGS   ?= -O2 -Wall
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

TARGET   = smtp-monitor
SRC      = smtp-monitor.c
LIBS     = -lpthread

# Auto-detect C standard: GCC < 5 (e.g. CentOS 7) defaults to C89,
# which doesn't support mixed declarations, for-loop initializers, etc.
# We detect the GCC major version and add -std=gnu99 if needed.
GCC_MAJOR := $(shell $(CC) -dumpversion 2>/dev/null | cut -d. -f1)
STD_FLAG  := $(shell [ "$(GCC_MAJOR)" -lt 5 ] 2>/dev/null && echo "-std=gnu99" || echo "")

# Detect ncurses via pkg-config, fallback to manual flags
NCURSES_CFLAGS := $(shell pkg-config --cflags ncurses 2>/dev/null || pkg-config --cflags ncursesw 2>/dev/null || echo "")
NCURSES_LIBS   := $(shell pkg-config --libs ncurses 2>/dev/null || pkg-config --libs ncursesw 2>/dev/null || echo "-lncurses")

CFLAGS  += $(STD_FLAG) $(NCURSES_CFLAGS)
LIBS    += $(NCURSES_LIBS)

.PHONY: all install uninstall clean check-deps help

all: check-deps $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)
	@echo ""
	@echo "Build successful: ./$(TARGET)"
	@echo "Run with: sudo ./$(TARGET)"

check-deps:
	@command -v $(CC) >/dev/null 2>&1 || { \
		echo "Error: $(CC) not found. Install gcc:"; \
		echo "  RHEL/AlmaLinux/Rocky/CentOS: sudo yum install gcc  (or sudo dnf install gcc)"; \
		echo "  Debian/Ubuntu:               sudo apt install gcc"; \
		exit 1; \
	}
	@echo '#include <ncurses.h>' | $(CC) -E - $(NCURSES_CFLAGS) >/dev/null 2>&1 || { \
		echo "Error: ncurses development headers not found. Install them:"; \
		echo "  RHEL/AlmaLinux/Rocky/CentOS: sudo yum install ncurses-devel  (or sudo dnf install ncurses-devel)"; \
		echo "  Debian/Ubuntu:               sudo apt install libncurses-dev"; \
		exit 1; \
	}

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "Installed to $(DESTDIR)$(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "Removed $(DESTDIR)$(BINDIR)/$(TARGET)"

clean:
	rm -f $(TARGET)

help:
	@echo "SMTP Connection Monitor - Build targets:"
	@echo ""
	@echo "  make              Build the binary"
	@echo "  make install      Install to $(BINDIR) (use DESTDIR for packaging)"
	@echo "  make uninstall    Remove from $(BINDIR)"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  CC=$(CC)  CFLAGS=$(CFLAGS)"
	@echo "  PREFIX=$(PREFIX)  DESTDIR=$(DESTDIR)"
	@echo ""
	@echo "Detected: GCC $(GCC_MAJOR)  STD_FLAG=$(STD_FLAG)"
