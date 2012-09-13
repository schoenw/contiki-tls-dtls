#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <stdio.h>
#include <string.h>
#include "netconf-light.h"
static struct etimer et;
extern uint8_t _end;
extern uint8_t __stack;
void StackPaint(void) __attribute__ ((naked)) __attribute__ ((section (".init1")));

void StackPaint(void)
{
#if 0
    uint8_t *p = &_end;

    while(p <= &__stack)
    {
        *p = 0xc5;
        p++;
    }
#else
    __asm volatile ("    ldi r30,lo8(_end)\n"
                    "    ldi r31,hi8(_end)\n"
                    "    ldi r24,lo8(0xc5)\n" /* STACK_CANARY = 0xc5 */
                    "    ldi r25,hi8(__stack)\n"
                    "    rjmp .cmp\n"
                    ".loop:\n"
                    "    st Z+,r24\n"
                    ".cmp:\n"
                    "    cpi r30,lo8(__stack)\n"
                    "    cpc r31,r25\n"
                    "    brlo .loop\n"
                    "    breq .loop"::);
#endif
}
PROCESS(udp_server_process, "1");
AUTOSTART_PROCESSES(&udp_server_process, &netconflight_process);//add &netconflight_process
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(udp_server_process, ev, data)
{

  PROCESS_BEGIN();
   etimer_set(&et, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);

 while(1) {
	PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
