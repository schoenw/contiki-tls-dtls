#ifndef __SYSMAN_ARCH_H
#define __SYSMAN_ARCH_H
#include "contiki-net.h"
#include "process.h"
#define GET_TEMPERATURE(unit) avr_get_temperature(unit)
#define GET_LCDMESSAGE() avr_get_lcdmessage();
#define GET_SYSUPTIME() avr_get_sysuptime();
#define GET_SYSCONTACT() avr_get_syscontact();
#define GET_SYSNAME() avr_get_sysname();
#define GET_IFNAME() avr_get_ifname();
#define GET_GLOBALIP6ADDRESS() avr_get_globalip6address();
#define GET_DEFAULTROUTER() avr_get_defaultrouter();
#define GET_SENTPACKETS() avr_get_sentpackets();
#define GET_RECEIVEDPACKETS() avr_get_receivedpackets();
#define GET_FAILSENT() avr_get_failsent();
#define GET_FAILRECEIVED() avr_get_failreceived();
#define GET_SENTOCTETS() avr_get_sentoctets();
#define GET_RECEIVEDOCTETS() avr_get_receivedoctets();
#define GET_SENTMCASTPACKETS() avr_get_sentmcastpackets();
#define GET_RECEIVEDMCASTPACKETS() avr_get_receivedmcastpackets();
int avr_get_temperature(char* unit);
char* avr_get_lcdmessage();
int avr_get_sysuptime();
char* avr_get_syscontact();
char* avr_get_sysname();
char* avr_get_ifname();
uip_ipaddr_t* avr_get_globalip6address();
uip_ipaddr_t* avr_get_defaultrouter();
int avr_get_sentpackets();
int avr_get_receivedpackets();
int avr_get_failsent();
int avr_get_failreceived();
int avr_get_sentoctets();
int avr_get_receivedoctets();
int avr_get_sentmcastpackets();
int avr_get_receivedmcastpackets();
void sysman_set_temp(char* value);
int myatoi(char* value);
#endif /*__SYSMAN_ARCH_H*/
