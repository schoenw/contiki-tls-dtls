#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/dtls/dtls.h>
//#include <avr/io.h>
#include <string.h>
//#include "raven-lcd.h"
#ifndef DEBUG
#define DEBUG DEBUG_PRINT
#endif
#include "net/uip-debug.h"

PROCESS(dtls_server_test_process, "DTLS server test process");
AUTOSTART_PROCESSES(&dtls_server_test_process);
static Connection* connection;
static struct etimer et;


static void dtls_handler(process_event_t ev, process_data_t data){
	if (ev == dtls_event){
		if (dtls_connected()){
			//raven_lcd_show_text("conn");
			PRINTF("CONNECTED\n");
			connection = (Connection*)data;
		} else if (dtls_newdata()){
			dtls_appdata[dtls_applen] = 0;
			PRINTF("GOT NEW DATA: %s\n",dtls_appdata);
			//raven_lcd_show_text(dtls_appdata);
		}
	}

}
PROCESS_THREAD(dtls_server_test_process, ev, data)
{
  PROCESS_BEGIN();
	DTLS_Listen(20220,1);
	while(1){
		PROCESS_YIELD();
		dtls_handler(ev, data);
	}
  PROCESS_END();
}
