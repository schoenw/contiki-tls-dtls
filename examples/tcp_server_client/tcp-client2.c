#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <avr/io.h>
#include "raven-lcd.h"
#include <string.h>
#include "stdio.h"

#define SEND_INTERVAL		5 * CLOCK_CONF_SECOND
static process_event_t tls_event;
static struct uip_conn *client_conn;
static struct process* calling_process;
static uip_ipaddr_t ipaddr1;
  static struct etimer et;
  static int message = 0;
/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
PROCESS(client_process, "client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static int connected =0 ;
/*---------------------------------------------------------------------------*/
static void
timeout_handler(void)
{
	      uip_send("hello", 5);
	      tcpip_poll_tcp(client_conn);//!!!!!!<<<<THIS IS A MUST!!!!without it the uip_process() is called due to the periodic
	      	  	  	  	  	  	  	  //timer and when that happens uip_slen is being set to 0, implying that nothing is to be sent
}


/*---------------------------------------------------------------------------*/
static void
set_connection_address(uip_ipaddr_t *ipaddr)
{
 uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x0010,0x021b,0x77ff,0xfeb5,0xd743); //laptop - wlan0
// uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xc8a7); //mote_short

}
static void connect(){
	process_start(&client_process, NULL);
}
static void tcp_send(char* toSend, int len){
	uip_send(toSend, len);
	tcpip_poll_tcp(client_conn);
}
static void tls_handler(process_event_t ev, process_data_t data){
	if(ev == tls_event){
		if (connected){
			raven_lcd_show_text("connected");
		}
	}
}
static void
tcpip_handler(){
	if (uip_connected()){
		tcp_send("client hello", 12);
		message = 1;
	}else
	if (uip_newdata()){
		((char *)uip_appdata)[uip_datalen()] = 0;
		raven_lcd_show_text((char*)uip_appdata);
		if (message == 1){
			tcp_send("client key exchange finished", 28);
			message = 2;
		} else if (message == 2){
			connected = 1;
			process_post(calling_process, tls_event, NULL);
		}
	}
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
	PROCESS_BEGIN();

  	set_connection_address(&ipaddr1);
  	calling_process = PROCESS_CURRENT();
  /* new connection with remote host */
  	connect();


  while(1) {

    PROCESS_YIELD();
    tls_handler(ev, data);

  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(client_process, ev, data)
{
	PROCESS_BEGIN();
	client_conn = tcp_connect(&ipaddr1, UIP_HTONS(3001), NULL);
	while(1){
		PROCESS_YIELD();
		if (ev == tcpip_event){
			tcpip_handler();
		}
	}
	PROCESS_END();
}
