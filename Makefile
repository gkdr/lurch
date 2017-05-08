### toolchain
#
CC ?= gcc

PKG_CONFIG ?= pkg-config
GLIB_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags glib-2.0)
GLIB_LDFLAGS ?= $(shell $(PKG_CONFIG) --libs glib-2.0)

LIBPURPLE_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags purple)
LIBPURPLE_LDFLAGS ?= $(shell $(PKG_CONFIG) --cflags purple) \
		     -L$(shell $(PKG_CONFIG) --variable=plugindir purple)

XML2_CONFIG ?= xml2-config
XML2_CFLAGS ?= $(shell $(XML2_CONFIG) --cflags)
XML2_LDFLAGS ?= $(shell $(XML2_CONFIG) --libs)

LIBGCRYPT_CONFIG ?= libgcrypt-config
LIBGCRYPT_LDFLAGS ?= $(shell $(LIBGCRYPT_CONFIG) --libs)

MKDIR = mkdir
MKDIR_P = mkdir -p
INSTALL = install
INSTALL_LIB = $(INSTALL) -m 755
INSTALL_DIR = $(INSTALL) -d -m 755
RM = rm
RM_RF = $(RM) -rf
CMAKE ?= cmake
CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS=-fPIC

### flags
#
LIBPURPLE_CFLAGS=$(shell $(PKG_CONFIG) --cflags purple)
LIBPURPLE_LDFLAGS=$(shell $(PKG_CONFIG) --cflags purple) \
		    -L$(shell $(PKG_CONFIG) --variable=plugindir purple)

PKGCFG_C=$(GLIB_CFLAGS) \
	 $(LIBPURPLE_CFLAGS) \
	 $(XML2_CFLAGS)

PKGCFG_L=$(GLIB_LDFLAGS) \
	 $(LIBPURPLE_LDFLAGS) \
	 $(XML2_LDFLAGS) \
	 $(LIBGCRYPT_LDFLAGS)

ifneq ("$(wildcard /etc/redhat-release)","")
	LJABBER= -lxmpp
else
	LJABBER= -ljabber
endif

HEADERS=-I$(HDIR)/jabber -I$(LOMEMO_SRC) -I$(AXC_SRC) -I$(AX_DIR)/src
CFLAGS += -std=c11 -Wall -g -Wstrict-overflow $(PKGCFG_C) $(HEADERS)
PLUGIN_CPPFLAGS=-DPURPLEPLUGINS
CPPFLAGS += -D_XOPEN_SOURCE=700 -D_BSD_SOURCE
LDFLAGS += -ldl -lm $(PKGCFG_L) $(LJABBER)


### directories
#
PURPLE_HOME_PLUGIN_DIR=$(HOME)/.purple/plugins
PURPLE_PLUGIN_DIR = $(shell $(PKG_CONFIG) --variable=plugindir purple)

LDIR=./lib
BDIR=./build
SDIR=./src
HDIR=./headers

LOMEMO_DIR=$(LDIR)/libomemo
LOMEMO_SRC=$(LOMEMO_DIR)/src
LOMEMO_BUILD=$(LOMEMO_DIR)/build
LOMEMO_PATH=$(LOMEMO_BUILD)/libomemo-conversations.a

AXC_DIR=$(LDIR)/axc
AXC_SRC=$(AXC_DIR)/src
AXC_BUILD=$(AXC_DIR)/build
AXC_PATH=$(AXC_BUILD)/libaxc-nt.a

AX_DIR=$(AXC_DIR)/lib/libsignal-protocol-c
AX_PATH=$(AX_DIR)/build/src/libsignal-protocol-c.a

VENDOR_LIBS=$(LOMEMO_PATH) $(AXC_PATH) $(AX_PATH)


### make rules
#
all: $(BDIR)/lurch.so

$(BDIR):
	$(MKDIR_P) build

$(AX_PATH):
	cd $(AX_DIR)/ && \
	   $(MKDIR_P) build && \
	   cd build && \
	   $(CMAKE) $(CMAKE_FLAGS) .. \
	   && $(MAKE)

$(AXC_PATH):
	$(MAKE) -C "$(AXC_DIR)" build/libaxc-nt.a

$(LOMEMO_PATH):
	$(MAKE) -C "$(LOMEMO_DIR)" build/libomemo-conversations.a

$(BDIR)/%.o: $(SDIR)/%.c $(BDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(PLUGIN_CPPFLAGS) -c $(SDIR)/$*.c -o $@

$(BDIR)/lurch.so: $(BDIR)/lurch.o $(VENDOR_LIBS)
	$(CC) -fPIC -shared $(CFLAGS) $(CPPFLAGS) $(PLUGIN_CPPFLAGS) \
		"$(BDIR)/lurch.o" $(VENDOR_LIBS) \
		-o $@ $(LDFLAGS)
$(BDIR)/lurch.a: $(BDIR)/lurch.o $(VENDOR_LIBS)
	$(AR) rcs $@ $^

install: $(BDIR)/lurch.so
	[ -e "$(DESTDIR)/$(PURPLE_PLUGIN_DIR)" ] || \
		$(INSTALL_DIR) "$(DESTDIR)/$(PURPLE_PLUGIN_DIR)"
	$(INSTALL_LIB) "$(BDIR)/lurch.so" "$(DESTDIR)/$(PURPLE_PLUGIN_DIR)/lurch.so"

install-home: $(BDIR)/lurch.so
	[ -e "$(PURPLE_HOME_PLUGIN_DIR)" ] || \
		$(INSTALL_DIR) "$(PURPLE_HOME_PLUGIN_DIR)"
	$(INSTALL_LIB) "$(BDIR)/lurch.so" "$(PURPLE_HOME_PLUGIN_DIR)/lurch.so"

clean:
	$(RM_RF) "$(BDIR)"

clean-all: clean
	$(MAKE) -C "$(LOMEMO_DIR)" clean
	$(MAKE) -C "$(AXC_DIR)" clean

.PHONY: clean clean-all install install-home

