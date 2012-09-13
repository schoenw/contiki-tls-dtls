#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <stdlib.h>

#include <string.h>

#include "sys/clock.h"

#ifndef DEBUG
#define DEBUG 1
#endif
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#endif


PROCESS(udp_process_receiver, "simple");
AUTOSTART_PROCESSES(&udp_process_receiver);
static struct etimer timer;


/*---------------------------------------------------------------------------*/
static void
udphandler(process_event_t ev, process_data_t data)
{
	
	if (ev == tcpip_event) {
	
		if(uip_connected()){
			
			uip_send("hello\n",strlen("hello\n"));
			
		}
 		if(uip_newdata()) {
			
			
			uip_send((char*)uip_appdata,uip_datalen());
							
			
		}
	
	} 
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_process_receiver, ev, data)
{

  PROCESS_BEGIN();
  PRINTF("Process test TCP listener started\n");

  etimer_set(&timer, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);

  tcp_listen(UIP_HTONS(3000));
  PRINTF("Listening on TCP port 3000\n");

  
  while(1) {
    PROCESS_YIELD();
    udphandler(ev, data);
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
