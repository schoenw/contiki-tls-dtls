#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <avr/io.h>
#include "raven-lcd.h"
#include <string.h>
#include "stdio.h"

#define SEND_INTERVAL		5 * CLOCK_CONF_SECOND

static struct uip_udp_conn *client_conn;
static uip_ipaddr_t ipaddr;
  static struct etimer et;
/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
timeout_handler(void)
{
	      uip_udp_packet_send(client_conn, "hello", 5);
	      if(etimer_expired(&et)) etimer_reset(&et);
}

static void
tcpip_handler(){
	
	if (uip_newdata()){
		((char *)uip_appdata)[uip_datalen()] = 0;
		raven_lcd_show_text((char*)uip_appdata);
	}
}
/*---------------------------------------------------------------------------*/
static void
set_connection_address(uip_ipaddr_t *ipaddr)
{
// uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x0010,0x021b,0x77ff,0xfeb5,0xd743); //laptop - wlan0
 uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xa4c6); //laptop - usb0
// uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xc8a7); //mote_short

}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
	PROCESS_BEGIN();

  	set_connection_address(&ipaddr);
  /* new connection with remote host */

 	 client_conn = udp_new(&ipaddr, UIP_HTONS(3001), NULL);
 	 etimer_set(&et, SEND_INTERVAL);
  while(1) {

    PROCESS_YIELD();
     if (ev == tcpip_event){
    	tcpip_handler();
    } else if (ev == PROCESS_EVENT_TIMER){
    	timeout_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
