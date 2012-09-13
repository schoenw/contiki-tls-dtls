#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/dtls/dtls.h>


PROCESS(dtls_server_test_process, "1");
AUTOSTART_PROCESSES(&dtls_server_test_process);
static Connection* connection;
static void dtls_handler(process_event_t ev, process_data_t data){

	if (ev == dtls_event){
		if (dtls_connected()){
		//	raven_lcd_show_text("conn");
			connection = (Connection*)data;
			//DTLS_Write(connection, "connected", 9);
		} else if (dtls_newdata()){
			//tls_appdata[tls_applen] = 0;
			dtls_appdata[dtls_applen] = 0;
			//raven_lcd_show_text(dtls_appdata);
			//DTLS_Write(connection, "world", 5);
		}
	}

}
PROCESS_THREAD(dtls_server_test_process, ev, data)
{
  PROCESS_BEGIN();
	DTLS_Listen(443,1);
	while(1){
		PROCESS_YIELD();
		dtls_handler(ev, data);
	}
  PROCESS_END();
}
