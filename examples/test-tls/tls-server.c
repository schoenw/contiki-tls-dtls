#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/tls/tls.h>
#include "raven-lcd.h"
#include <avr/io.h>
static struct etimer et;

PROCESS(tls_server_test_process, "1");
AUTOSTART_PROCESSES(&tls_server_test_process);
static Connection* connection;
static void tls_handler(process_event_t ev, process_data_t data){

	if (ev == tls_event){
		if (tls_connected()){
			//raven_lcd_show_text("conn");
			connection = (Connection*)data;
			//TLS_Write(connection, "1", 1);
			//etimer_set(&et, CLOCK_CONF_SECOND);
		} /*else if (tls_newdata()){
			tls_appdata[5] = 0;
			TLS_Write(connection, "1", 1);
		}*/
	} else if (ev == PROCESS_EVENT_TIMER){
		if (etimer_expired(&et)){
			tls_write(connection, "1",1);
			etimer_set(&et, CLOCK_CONF_SECOND);
		}
	}

}
PROCESS_THREAD(tls_server_test_process, ev, data)
{
  PROCESS_BEGIN();
	tls_listen(443,1);
	while(1){
		PROCESS_YIELD();
		tls_handler(ev, data);
	}
  PROCESS_END();
}
