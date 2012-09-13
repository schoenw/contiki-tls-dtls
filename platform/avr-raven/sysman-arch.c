#include "sysman-arch.h"
#include "contiki-conf.h"
#include "raven-lcd.h"
#include "string.h"
#include "rf230bb.h"
#include "sys/pt.h"
#include "uip.h"
static int temperature = -100;
int avr_get_temperature(char* unit){
	//raven_get_temperature(unit);
	
	return temperature;
}

char* avr_get_lcdmessage(){
	return "hello";
}

int avr_get_sysuptime(){
	return clock_seconds();
}

char* avr_get_syscontact(){
	return "admin@eecs.jacobs-university.de";
}

char* avr_get_sysname(){
	return "sysman-test";
}


char* avr_get_ifname(){
	return "wpan0";
}

uip_ipaddr_t* avr_get_globalip6address(){
	uip_ds6_addr_t* myaddr;
	myaddr = uip_ds6_get_global(ADDR_PREFERRED);
	if (myaddr!=NULL){
		return &myaddr->ipaddr;
	} else return NULL;
}

uip_ipaddr_t* avr_get_defaultrouter(){
	return uip_ds6_defrt_choose();

}

int avr_get_sentpackets(){ //defined RADIOSTATS in rf230bb.h
	#if RADIOSTATS
		extern uint16_t RF230_sendpackets;
		return RF230_sendpackets;
	#else 
		return 0;
	#endif
}

int avr_get_receivedpackets(){
	#if RADIOSTATS
		extern uint16_t RF230_receivepackets;
		return RF230_receivepackets;
	#else 
		return 0;
	#endif
}

int avr_get_failsent(){
	#if RADIOSTATS
		extern uint16_t RF230_sendfail; 
		return RF230_sendfail;
	#else 
		return 0;
	#endif
}

int avr_get_failreceived(){
	#if RADIOSTATS
		extern uint16_t RF230_receivefail;
		return RF230_receivefail;
	#else 
		return 0;
	#endif
}

int avr_get_sentoctets(){
	#if RADIOSTATS
		extern uint32_t RF230_sendOctets;
		return RF230_sendOctets;
	#else
		return 0;
	#endif
}

int avr_get_receivedoctets(){
	#if RADIOSTATS
		extern uint32_t RF230_receiveOctets;
		return RF230_receiveOctets;
	#else
		return 0;
	#endif
}

int avr_get_sentmcastpackets(){ //defined MCASTSTATS in uip.h
	#if MCASTSTATS
		extern uint16_t sentMcastPkts;
		return sentMcastPkts;
	#else 
		return 0;
	#endif
}

int avr_get_receivedmcastpackets(){
	#if MCASTSTATS
		extern uint16_t rcvdMcastPkts;
		return rcvdMcastPkts;
	#else 
		return 7;
	#endif
}
int myatoi(char* value){
	int answer = 0;
	int i = 0;
	if (value[0]=='-') i=1;
	for (; i < strlen(value); i++){
		if (value[i]==' ') break;
		answer*=10;
		answer+=((int)value[i]-48);
	}
	return value[0]=='-'? -answer:answer;
}

void sysman_set_temp(char* value){
	temperature = myatoi(value);
}
