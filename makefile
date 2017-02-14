PURPLE_PLUGIN_DIR=~/.purple/plugins
PIDGIN_DIR=./pidgin-2.11.0
PURPLE_PLUGIN_SRC_DIR=$(PIDGIN_DIR)/libpurple/plugins

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

AX_DIR=$(AXC_DIR)/lib/libaxolotl-c
AX_PATH=$(AX_DIR)/build/src/libaxolotl-c.a

FILES=$(LOMEMO_PATH) $(AXC_PATH) $(AX_PATH)

HEADERS=-I$(HDIR)/jabber -I$(LOMEMO_SRC) -I$(AXC_SRC) -I$(AX_DIR)/src

PKGCFG_C=$(shell pkg-config --cflags glib-2.0 purple)  $(shell xml2-config --cflags)
PKGCFG_L=$(shell pkg-config --libs purple glib-2.0 sqlite3 mxml) $(shell xml2-config --libs) -L$(shell pkg-config --variable=plugindir purple) $(shell libgcrypt-config --libs)

CFLAGS=-std=c11 -Wall -g -Wstrict-overflow -D_XOPEN_SOURCE=700 -D_BSD_SOURCE $(PKGCFG_C) $(HEADERS)
LFLAGS= -ldl -lm $(PKGCFG_L) -ljabber


all: $(BDIR)/lurch.so

$(BDIR):
	mkdir -p build
	
$(AX_PATH):
	cd $(AXC_DIR)/lib/libaxolotl-c/ && mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make
	
$(AXC_PATH):
	cd $(AXC_DIR) && make build/libaxc-nt.a
	
$(LOMEMO_PATH):
	cd $(LOMEMO_DIR) && make build/libomemo-conversations.a
	
$(BDIR)/lurch.so: $(SDIR)/lurch.c $(AX_PATH) $(AXC_PATH) $(LOMEMO_PATH) $(BDIR)
	gcc $(CFLAGS) -fPIC -c $(SDIR)/lurch.c -o $(BDIR)/lurch.o
	gcc -fPIC -shared $(CFLAGS) $(BDIR)/lurch.o $(FILES) -o $@ $(LFLAGS)
	
install: $(BDIR)/lurch.so
	mkdir -p $(PURPLE_PLUGIN_DIR)
	cp $(BDIR)/lurch.so $(PURPLE_PLUGIN_DIR)/lurch.so

.PHONY: clean
clean:
	rm -rf $(LOMEMO_BUILD)
	rm -rf $(AXC_BUILD)
	rm -rf $(AX_DIR)/build
	rm -rf $(BDIR)
