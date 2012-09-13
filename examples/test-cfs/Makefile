all: tcp-server

UIP_CONF_IPV6=1
#APPS=raven-lcd-interface ntpd netconf-light syslog
COFFEE_FILES=3
COFFEE_ADDRESS=0x19000

ifdef TLS
CFLAGS+= -DTLS=1
endif
CONTIKI = ../..
include $(CONTIKI)/Makefile.include
CONTIKI_SOURCEFILES += testinit.c

