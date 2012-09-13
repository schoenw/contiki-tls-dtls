#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <avr/io.h>
#include "raven-lcd.h"
#include <string.h>

static struct etimer et;
static struct uip_udp_conn *server_conn;
PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
#define UDP_IP_BUF   ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

/*---------------------------------------------------------------------------*/

static void
tcpip_handler(void)
{
	
  if(uip_newdata()) {
	((char *)uip_appdata)[uip_datalen()] = 0;
	raven_lcd_show_text((char*)uip_appdata);
	uip_ipaddr_copy(&server_conn->ripaddr, &UDP_IP_BUF->srcipaddr);
 	server_conn->rport = UDP_IP_BUF->srcport;
	uip_udp_packet_send(server_conn, "world", 5);
	memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
 	server_conn->rport = 0;
  }
}

PROCESS_THREAD(udp_server_process, ev, data)
{

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  server_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(server_conn, UIP_HTONS(3000));

  while(1) {
  
  	PROCESS_YIELD();
  	if (ev == tcpip_event){
  		tcpip_handler();
  	}

  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
