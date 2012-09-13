#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "hmac_sha2.h"

static struct etimer et;
PROCESS(udp_server_process, "1");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(udp_server_process, ev, data)
{

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  hmac_sha256("",0,"",0,"",0);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
