/*
 * Copyright (c) 2011, Vladislav Perelman
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

#ifndef __SYSMAN_H
#define __SYSMAN_H
#include "contiki.h"
#include "contiki-net.h"

static int lastTempUpdate=0;
void freeMemory();
///////////////////////////////////////////
////////////OPERATIONAL STATE//////////////
///////////////////////////////////////////
/**
	retrieve temperature (C or F)
*/
int getTemperature(char* unit);

int getLastTempUpdate();
/**
	retrieve system up time
*/
int getSysUpTime();

/**
	retrieve global ipv6 address
*/
uip_ipaddr_t* getGlobalIP6Address();

/**
	retrieve radio statistics
*/
int getSentPackets();

int getReceivedPackets();

int getFailSent();

int getFailReceived();

int getSentOctets();

int getReceivedOctets();

int getSentMcastPackets();

int getReceivedMcastPackets();

///////////////////////////////////////////
//////////////CONFIGURATION////////////////
///////////////////////////////////////////

/**
	retrieve LCD message
*/
char* getLCDMessage();

/**
	retrieve system contact 
*/
char* getSysContact();

/**
	retrieve system name
*/
char* getSysName();

/**
	retrieve system describtion 
*/
char* getSysDesc();

/**
	retrieve system location
*/
char* getSysLocation();

/**
	retrieve ifName
*/
char* getIfName();

/**
	retrieve IP address of the default router
*/
uip_ipaddr_t* getDefaultRouter();

/**
	retrieve IP address of the syslog server (if not provided then it's the default router)
*/
uip_ipaddr_t* getSyslogServer();

/**
	retrieve IP address of the NTP server (if not provided then it's the default router)
*/
uip_ipaddr_t* getNTPServer();
#endif /*__SYSMAN_H*/
