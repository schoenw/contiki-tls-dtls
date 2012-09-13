#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/dtls/dtls.h>
#include <avr/io.h>
#include <string.h>
#include "raven-lcd.h"
#define SEND_INTERVAL 1 * CLOCK_CONF_SECOND
#define CLOSE_INTERVAL 120 * CLOCK_CONF_SECOND
PROCESS(dtls_server_test_process, "DTLS server test process");
AUTOSTART_PROCESSES(&dtls_server_test_process);
static Connection* connection;
static struct etimer et;
static struct etimer et2;
static char* hello_msg = "hello";
static void dtls_handler(process_event_t ev, process_data_t data){
if (ev == dtls_event){
		if (dtls_rehandshake()){
			etimer_stop(&et);
		} else
		if (dtls_connected()){
			raven_lcd_show_text("conn");
			connection = (Connection*)data;
			etimer_set(&et, SEND_INTERVAL);
			DTLS_Write(connection, hello_msg, strlen(hello_msg));
		} else if (dtls_newdata()){
			dtls_appdata[dtls_applen] = 0;
			
			raven_lcd_show_text(dtls_appdata);
			etimer_set(&et, CLOSE_INTERVAL);
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		if (etimer_expired(&et)){
			DTLS_Write(connection, hello_msg, strlen(hello_msg));
			etimer_reset(&et);
		}
		if (etimer_expired(&et2)){
			DTLS_Close(connection);
			etimer_stop(&et);
			etimer_stop(&et2);
		}
	}

	

}
PROCESS_THREAD(dtls_server_test_process, ev, data)
{
  PROCESS_BEGIN();
 	etimer_set(&et2, CLOSE_INTERVAL);
	DTLS_Listen(443,1);
	while(1){
		PROCESS_YIELD();
		dtls_handler(ev, data);
	}
  PROCESS_END();
}
