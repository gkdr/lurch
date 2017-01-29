LO_CFLAGS=-g -std=c11 -Wall -Wextra -Wpedantic -Wstrict-overflow -fno-strict-aliasing -funsigned-char -D_XOPEN_SOURCE=700 -D_BSD_SOURCE -fno-builtin-memset `pkg-config --cflags glib-2.0` -DOMEMO_XMLNS='"lurch"'

PURPLE_PLUGIN_DIR=~/.purple/plugins
PIDGIN_DIR=./pidgin-2.11.0
PURPLE_PLUGIN_SRC_DIR=$(PIDGIN_DIR)/libpurple/plugins

LDIR=./lib

LOMEMO_DIR=$(LDIR)/libomemo
LOMEMO_SRC=$(LOMEMO_DIR)/src
LOMEMO_BUILD=$(LOMEMO_DIR)/build

AXC_DIR=$(LDIR)/axc
AXC_SRC=$(AXC_DIR)/src
AXC_BUILD=$(AXC_DIR)/build

LFLAGS=-lmxml -pthread -ldl -lm -lcrypto -lglib-2.0 -lxml2 -L/usr/lib/purple-2/ -ljabber -lsqlite3 -laxolotl-c

export PLUGIN_LIBS= ../../../$(LOMEMO_BUILD)/libomemo.la ../../../$(AXC_BUILD)/libaxc.la  $(LFLAGS)
export PLUGIN_CFLAGS=-I/usr/include/libxml2

all: lurch

.PHONY: libomemo
libomemo: $(LOMEMO_DIR)
	cd $(LOMEMO_DIR) && make libomemo-lurch
	
libaxc: $(AXC_DIR)
	cd $(AXC_DIR) && make $@

lurch: libomemo libaxc $(PURPLE_PLUGIN_SRC_DIR)/lurch.c
	cd $(PURPLE_PLUGIN_SRC_DIR) && make $@.so && mv $@.so $(PURPLE_PLUGIN_DIR)

.PHONY: clean
clean:
	rm -rf $(LOMEMO_BUILD)
	rm -rf $(AXC_BUILD)
