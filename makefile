### toolchain
#
CC ?= gcc
PKG_CONFIG ?= pkg-config
XML2_CONFIG ?= xml2-config
LIBGCRYPT_CONFIG ?= libgcrypt-config
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
PKGCFG_C=$(shell $(PKG_CONFIG) --cflags glib-2.0 purple) \
		 $(shell $(XML2_CONFIG) --cflags)

PKGCFG_L=$(shell $(PKG_CONFIG) --libs purple glib-2.0 sqlite3 mxml) \
		 $(shell $(XML2_CONFIG) --libs) \
		 -L$(shell $(PKG_CONFIG) --variable=plugindir purple) \
		 $(shell $(LIBGCRYPT_CONFIG) --libs)
		 
ifneq ("$(wildcard /etc/redhat-release)","")
    LJABBER= -lxmpp
else
	LJABBER= -ljabber
endif

HEADERS=-I$(HDIR)/jabber -I$(LOMEMO_SRC) -I$(AXC_SRC) -I$(AX_DIR)/src
CFLAGS += -std=c11 -Wall -g -Wstrict-overflow $(PKGCFG_C) $(HEADERS)
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

FILES=$(LOMEMO_PATH) $(AXC_PATH) $(AX_PATH)


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

$(BDIR)/lurch.so: $(SDIR)/lurch.c $(AX_PATH) $(AXC_PATH) $(LOMEMO_PATH) $(BDIR)
	$(CC) -fPIC $(CFLAGS) $(CPPFLAGS) \
		-c "$(SDIR)/lurch.c" \
		-o "$(BDIR)/lurch.o"
	$(CC) -fPIC -shared $(CFLAGS) $(CPPFLAGS) \
		"$(BDIR)/lurch.o" $(FILES) \
		-o $@ $(LDFLAGS)

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

