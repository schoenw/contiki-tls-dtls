all: dtls-client3 dtls-server3
	$(MAKE) $(MAKEFLAGS) ROLE=server dtls-server3
	$(MAKE) $(MAKEFLAGS) clean
	$(MAKE) $(MAKEFLAGS) ROLE=client dtls-client3

ifneq ($(ROLE),client)
	CFLAGS += -DHARD_CODED_ADDRESS=\"aaaa::02:232\"
else
	CFLAGS += -DHARD_CODED_ADDRESS=\"aaaa::02:230\"
endif
DTLS=1

#MMEM_CONF_SIZE=512
UIP_CONF_IPV6=1
APPS=ntpd raven-lcd-interface

CONTIKI = ../..

include $(CONTIKI)/Makefile.include

