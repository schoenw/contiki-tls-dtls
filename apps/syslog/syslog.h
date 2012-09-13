/* -----------------------------------------------------------------------------
 * Syslog implementation for Contiki
 *
 * Copyright (C) 2011 Anuj Sehgal <s.anuj@jacobs-university.de>
 *
 * This program is part of free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef __SYSLOG_H__
#define __SYSLOG_H__

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "lib/petsciiconv.h"
#include <string.h>
#include "mac.h"
#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

//#define MAX_PAYLOAD_LEN		256
#define MAX_PAYLOAD_LEN		UIP_APPDATA_SIZE
#define SYSLOG_PORT             514

#define FAC_KERNEL 0
#define FAC_USER 1
#define FAC_MAIL 2
#define FAC_SYSTEM 3
#define FAC_SECURITY 4
#define FAC_SYSLOGD 5
#define FAC_PRINTER 6
#define FAC_NEWS 7
#define FAC_UUCP 8
#define FAC_CLOCK 9
#define FAC_AUTH 10
#define FAC_FTPD 11
#define FAC_NTP 12
#define FAC_AUDIT 13
#define FAC_ALERT 14
#define FAC_CLOCK2 15
#define FAC_LOCAL0 16
#define FAC_LOCAL1 17
#define FAC_LOCAL2 18
#define FAC_LOCAL3 19
#define FAC_LOCAL4 20
#define FAC_LOCAL5 21
#define FAC_LOCAL6 22
#define FAC_LOCAL7 23

#define SEV_EMERGENCY 0
#define SEV_ALERT 1
#define SEV_CRITICAL 2
#define SEV_ERROR 3
#define SEV_WARNING 4
#define SEV_NOTICE 5
#define SEV_INFO 6
#define SEV_DEBUG 7

/*---------------------------------------------------------------------------*/
static void
getmyip(const uip_ipaddr_t *addr, char *ipaddr){
  uint16_t a;
  int i, f;
  
  sprintf(ipaddr, "");

  for(i = 0, f = 0; i < sizeof(uip_ipaddr_t); i += 2) {
    a = (addr->u8[i] << 8) + addr->u8[i + 1];
    if(a == 0 && f >= 0) {
      if(f++ == 0) {
        sprintf(ipaddr, "%s::", ipaddr);
      }
    } else {
      if(f > 0) {
        f = -1;
      } else if(i > 0) {
        sprintf(ipaddr, "%s:", ipaddr);
      }
      sprintf(ipaddr, "%s%x", ipaddr, a);
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
syslog_msg(char *output, int facility, int severity, struct process *p, char *message){
  char name[40];
  char myip[40];
  int i;
  uint8_t state;

  //get name of process
  strncpy(name, ((struct process *)p)->name, 40);
  petsciiconv_toascii(name, 40);
  //process name done

  //get the main IP address of the node
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      break;
    }
  }
  getmyip(&uip_ds6_if.addr_list[i].ipaddr, myip);
  //IP address section done
  
  sprintf(output, "<%d>1 - %s %s %p - - %s",facility*8+severity, myip, name==NULL?"-":name, p, message);
}
/*---------------------------------------------------------------------------*/
static void 
syslog_send(char *buf, const uip_ipaddr_t *addr){
  static struct uip_udp_conn *udp_con = NULL;
  if (udp_con == NULL) {
    udp_con = udp_new(addr, UIP_HTONS(SYSLOG_PORT), NULL);
  }
  if(addr == NULL && uip_ds6_defrt_choose() != NULL) {
    uip_ipaddr_copy(&udp_con->ripaddr, uip_ds6_defrt_choose());
  }
  if(addr != NULL) {
    uip_ipaddr_copy(&udp_con->ripaddr, addr);
  }
  uip_udp_packet_send(udp_con, buf, strlen(buf));
}
/*---------------------------------------------------------------------------*/
#endif /* __SYSLOG_H__ */
