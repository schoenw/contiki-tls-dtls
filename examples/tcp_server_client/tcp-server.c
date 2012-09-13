#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <avr/io.h>
#include "raven-lcd.h"
#include <string.h>

static struct etimer et;
PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
static int more_to_send = 0;
static void
tcpip_handler(void)
{
	if (uip_connected()){
		uip_send("hello",5);
		more_to_send = 1;
	} else
  if(uip_newdata()) {
	((char *)uip_appdata)[uip_datalen()] = 0;
	raven_lcd_show_text((char*)uip_appdata);
  }
}

PROCESS_THREAD(udp_server_process, ev, data)
{

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  tcp_listen(UIP_HTONS(3000));
  etimer_set(&et, CLOCK_CONF_SECOND);

  while(1) {
  
  	PROCESS_YIELD();
  	if (more_to_send){
  		uip_send("more",4);
  		more_to_send = 0;
  	} else
  	tcpip_handler();

  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
