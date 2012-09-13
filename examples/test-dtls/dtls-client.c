/*
 * Example client application using DTLS library
 * TLS implementation for Contiki OS
 * Copyright (c) 2012, Vladislav Perelman <vladislav.perelman@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include <contiki.h>
#include <contiki-net.h>
#include <contiki-lib.h>
#include <net/dtls/dtls.h>
#include <string.h>
#include "lib/mmem.h"
#define SEND_INTERVAL 1 * CLOCK_CONF_SECOND
#define CLOSE_INTERVAL 120 * CLOCK_CONF_SECOND

PROCESS(dtls_client_test_process, "DTLS client");
AUTOSTART_PROCESSES(&dtls_client_test_process);
static Connection* connection;
static struct etimer et;
static struct etimer et2;
static char* hello_msg = "Hello World";
static uip_ipaddr_t ipaddr;
static void dtls_handler(process_event_t ev, process_data_t data){
	if (ev == dtls_event){
		if (dtls_rehandshake()){
			etimer_stop(&et);
		} else
		if (dtls_connected()){
			connection = (Connection*)data;
			etimer_set(&et, SEND_INTERVAL);
			DTLS_Write(connection, hello_msg, 11);
		} else if (dtls_newdata()){
			dtls_appdata[dtls_applen] = 0;
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		if (etimer_expired(&et)){
			DTLS_Write(connection, hello_msg, 11);
			etimer_reset(&et);
		}
		if (etimer_expired(&et2)){
			DTLS_Close(connection);
			etimer_stop(&et);
			etimer_stop(&et2);
		}
	}


}
static void set_connection_address(uip_ipaddr_t *ipaddr)
{
	// use uip_ip6addr to set the address of the server to connect to
	 uip_ip6addr(ipaddr, 0x2001,0x0638,0x0709,0x000a,0x0011,0x22ff,0xfe17,0xa4c6);
}

PROCESS_THREAD(dtls_client_test_process, ev, data)
{
  PROCESS_BEGIN();
	
	set_connection_address(&ipaddr);
	etimer_set(&et, CLOCK_CONF_SECOND*10);
  	PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  	etimer_set(&et2, CLOSE_INTERVAL);
	DTLS_Connect(&ipaddr, 4433);
	while(1){
		PROCESS_YIELD();
		dtls_handler(ev, data);
	}
  PROCESS_END();
}
