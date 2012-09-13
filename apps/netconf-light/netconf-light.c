/*
 * Copyright (c) 2011, Nokia Siemens Networks
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
/*
 * This is an implementation of the NETCONF Light protocol.
 * 
 */
#include "netconf-light.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <stdlib.h>
#include "simplexml2.h"
#include <string.h>
#include <avr/pgmspace.h>
#include "cfs-coffee.h"
#include "raven-lcd.h"
#include <avr/io.h>
//#include "testinit.c"
#include "sys/clock.h"
#include "stdio.h"
#if TLS
#include "net/tls/tls.h"
#endif

//#include "sysman.h"

#define DATA_LEN 1200
#define HANDLER_ERROR 255
#define HANDLER_UNINITIALIZED 0
#define HANDLER_HELLO 1
#define HANDLER_RPC 2
#define HANDLER_GET_CONFIG 3
#define HANDLER_SOURCE 4
#define HANDLER_RCVD_HELLO 5
#define HANDLER_COPY_CONFIG 6
#define HANDLER_COPY_CONFIG_TARGET 7
#define HANDLER_COPY_CONFIG_SOURCE 8
#define HANDLER_COPY_CONFIG_RUNNING 9
#define HANDLER_COPY_CONFIG_RUNNING_CONFIG 10
#define HANDLER_LOCK 12
#define HANDLER_LOCK_TARGET 13
#define HANDLER_GET 14
#define LCD 1
//error list
//Tags
#define IN_USE 0
#define INVALID_VALUE 1
#define TOO_BIG 2
#define MISSING_ATTRIBUTE 3
#define BAD_ATTRIBUTE 4
#define UNKNOWN_ATTRIBUTE 5
#define MISSING_ELEMENT 6
#define BAD_ELEMENT 7
#define UNKNOWN_ELEMENT 8
#define UNKNOWN_NAMESPACE 9
#define ACCESS_DENIED 10
#define LOCK_DENIED 11
#define OPERATION_NOT_SUPPORTED 12
#define OPERATION_FAILED 13
//Type
#define APPLICATION 0
#define RPC 1
#define PROTOCOL 2
#if !CONTIKI_TARGET_AVR_RAVEN
static char* error_tags[] = {"in-use","invalid-value", "too-big","missing-attribute","bad-attribute","unknown-attribute","missing-element","bad-element","unknown-element","unknown-namespace","access-denied","lock-denied","operation-not-permitted","operation-failed"};
static char* error_types[]= {"application","rpc","protocol"};
#else
const char inuse[] PROGMEM = "in-use";
const char invalidvalue[] PROGMEM = "invalid-value";
const char toobig[] PROGMEM = "too-big";
const char missingattribute[] PROGMEM = "missing-attribute";
const char badattribute[] PROGMEM = "bad-attribute";
const char unknownattribute[] PROGMEM = "unknown-attribute";
const char missingelement[] PROGMEM = "missing-element";
const char badelement[]  PROGMEM = "bad-element";
const char uknownnamespace[] PROGMEM = "uknown-namespace";
const char accessdenied[] PROGMEM = "access-denied";
const char lockdenied[]  PROGMEM = "lock-denied";
const char operationnotpermitted[] PROGMEM = "operation-not-permitted";
const char operationfailed[] PROGMEM = "operation-failed";
const char *error_tags[] PROGMEM = {
	inuse,
	invalidvalue,
	toobig,
	missingattribute,
	badattribute,
	unknownattribute,
	missingelement,
	badelement,
	uknownnamespace,
	accessdenied,
	lockdenied,
	operationnotpermitted,
	operationfailed
};
const char applicationtype[] PROGMEM = "application";
const char rpctype[] PROGMEM = "rpc";
const char protocoltype[] PROGMEM = "protocol";
const char *error_types[] PROGMEM = {
	applicationtype,
	rpctype,
	protocoltype
};
#endif
PROCESS(netconflight_process, "netconf-light");
static clock_time_t start = 0;
static struct etimer timer;
static char output[220];
static char* messageid;
static char* replyattr[10];
static uint8_t rpc=0;
static uint8_t parts = 0;
static uint8_t expected_more = 0;
static uint8_t more_to_send =0;
static uint8_t has_extra = 0;
static int extra_position = 0;
static uint8_t from_draft = 0;
static uint16_t input_processed = 0;
static uint16_t input_length = 0;
static int chunk_size=0;
static int position = 0;
static int outputsize = 0;
static uint8_t state = HANDLER_UNINITIALIZED;
static uint8_t timeout = 0;
static volatile unsigned int config_offset=0;
static uint8_t config = 0;
static uint8_t netconf1 = 0;
static XmlWriter* xmlWriter;
static char* invalid_tag = "invalid tag";
static uint8_t connected = 0;
static uint8_t locked = 0;
static uint8_t locking = 0;
static uint8_t compliant = 1;
static uint8_t foundCopyConfig = 0;
#if TLS
static Connection* connection;
static uint8_t wait_for_ack = 0;
#endif
MEMB(pool, XmlWriter,1);
#if CONTIKI_TARGET_AVR_RAVEN
const char hello_message[] PROGMEM = "<?xml version='1.0' encoding='UTF-8'?><hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities><session-id>1</session-id></hello>";
const char base1[] PROGMEM = "urn:ietf:params:netconf:base:1.1";
const char xmlstart[] PROGMEM = "<?xml version='1.0' encoding='UTF-8'?>";
const char running[] PROGMEM = "running";
const char source[] PROGMEM = "source";
const char copyconfig[] PROGMEM = "copy-config";
const char getconfig[] PROGMEM = "get-config";
const char configstr[] PROGMEM = "config";
const char target[] PROGMEM = "target";
const char candidate[] PROGMEM = "candidate";
const char startup[] PROGMEM = "startup";
const char rpcerror[] PROGMEM = "rpc-error";
const char error_type[] PROGMEM = "error-type";
const char error_tag[] PROGMEM = "error-tag";
const char error_severity[] PROGMEM = "error-severity";
const char error_message[] PROGMEM = "error-message";
const char rpcreply[] PROGMEM = "rpc-reply";
const char error[] PROGMEM = "error";
const char message_id[] PROGMEM = "message-id";
const char configxml[] PROGMEM = "/config.xml";
const char inputxml[] PROGMEM = "/input.xml";
const char draftxml[] PROGMEM = "/draft.xml";
const char namedummy[] PROGMEM = "<name>dummy</name>";
const char locationhere[] PROGMEM = "<location>here</location>";
const char pskidentitytag[] PROGMEM = "<psk><psk-identity>thisisme</psk-identity>";
const char usernametag[] PROGMEM = "<user-name>someuser</user-name>";
const char keytag[] PROGMEM = "<key>abcdefghijklmnopqrstuvwxyz123456</key></psk>";
const char lcdhello[] PROGMEM = "<lcd>Hello</lcd>\0";
const char update[] PROGMEM = "update";
const char sysuptime[] PROGMEM = "sysUpTime";
const char globalip[] PROGMEM = "globalIP";
const char ipformat[] PROGMEM = " %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ";
const char outputformat[] PROGMEM = "\n#%d\n%s\n##\n\0";
const char packetssent[] PROGMEM = "packetsSent";
const char packetsreceived[] PROGMEM = "packetsReceived";
const char failsent[] PROGMEM = "failSent";
const char failreceived[] PROGMEM = "failReceived";
const char octetssent[] PROGMEM = "octetsSent";
const char octetsreceived[] PROGMEM = "octetsReceived";
const char mcastsent[] PROGMEM = "mcastSent";
const char mcastreceived[] PROGMEM = "mcastReceived";
const char contact[] PROGMEM = "contact";
const char location[] PROGMEM = "location";
const char capabilities[] PROGMEM = "capabilities";
const char capability[] PROGMEM = "capability";
const char hello[] PROGMEM = "hello";
const char closesession[] PROGMEM = "close-session";
const char lock[] PROGMEM = "lock";
const char unlock[] PROGMEM = "unlock";
const char get[] PROGMEM = "get";
const char killsession[] PROGMEM = "kill-session";
const char *strings[] PROGMEM = {
		rpcreply, //0
		message_id, //1
		rpcerror, //2
		error_type, //3
		error_tag, //4
		error_severity, //5
		error_message, //6
		configxml, //7
		namedummy, //8
		locationhere, //9
		lcdhello,//10
		update, //11
		sysuptime, //12
		globalip, //13
		ipformat,  //14
		packetssent, //15
		packetsreceived, //16
		failsent, //17
		failreceived, //18
		octetssent, //19
		octetsreceived, //20
		mcastsent, //21
		mcastreceived, //22
		inputxml, //23
		draftxml, //24
		outputformat, //25
		pskidentitytag, //26
		usernametag, //27
		keytag //28
};
#else
const char xmlstart[] = "<?xml version='1.0' encoding='UTF-8'?>";
static void hello(XmlWriter* xmlWriter){
	simpleXmlStartElement(xmlWriter,NULL,"hello");
	simpleXmlAddAttribute(xmlWriter,NULL,"xmlns","urn:ietf:params:xml:ns:netconf:base:1.1");
	simpleXmlStartElement(xmlWriter,NULL,"capabilities");
	simpleXmlStartElement(xmlWriter,NULL,"capability");
	simpleXmlCharacters(xmlWriter,"urn:ietf:params:netconf:base:1.0");
	simpleXmlEndElement(xmlWriter,NULL,"capability");
	simpleXmlEndElement(xmlWriter,NULL,"capabilities");
	simpleXmlStartElement(xmlWriter,NULL,"session-id");
	simpleXmlCharacters(xmlWriter,"1");
	simpleXmlEndElement(xmlWriter,NULL,"session-id");
	simpleXmlEndElement(xmlWriter,NULL,"hello");
	simpleXmlEndDocument(xmlWriter);
}
#endif

#if CONTIKI_TARGET_AVR_RAVEN
extern unsigned long seconds;
#else
clock_time_t systemStartTime;
#endif

unsigned long getSysUpTime()
{
    #if CONTIKI_TARGET_AVR_RAVEN
        return seconds * 100;
    #else
        return (clock_time() - systemStartTime)/ 10;
    #endif
}

static void rpc_reply(XmlWriter* xmlWriter, char* messageid, const char** replyattr){

#if CONTIKI_TARGET_AVR_RAVEN
	char buffer[30];
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[0])));
	simpleXmlStartElement(xmlWriter, NULL, buffer);
#else
	simpleXmlStartElement(xmlWriter, NULL, "rpc-reply");
#endif
	if (strcmp(messageid,"")!=0){
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[1])));
	simpleXmlAddAttribute(xmlWriter,NULL,buffer,messageid);
#else
	simpleXmlAddAttribute(xmlWriter,NULL,"message-id",messageid);
#endif
	}

	short int tmp = 0;
	while (replyattr[tmp]!=NULL){	
		if (!strcmp(replyattr[tmp],"")){
			simpleXmlAddAttribute(xmlWriter,NULL,(char*)replyattr[tmp+1],(char*)replyattr[tmp+2]);
		}
		else {simpleXmlAddAttribute(xmlWriter,replyattr[tmp],replyattr[tmp+1],replyattr[tmp+2]);}
		tmp+=3;
	}
}

static void rpc_error(XmlWriter* xmlWriter, int type, int tag, char* message){
#if CONTIKI_TARGET_AVR_RAVEN
	char buffer[25];
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[2])));
	simpleXmlStartElement(xmlWriter,NULL,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[3])));
	simpleXmlStartElement(xmlWriter,NULL,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(error_types[type])));
	simpleXmlCharacters(xmlWriter,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[3])));
	simpleXmlEndElement(xmlWriter,NULL,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[4])));
	simpleXmlStartElement(xmlWriter,NULL,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(error_tags[tag])));
	simpleXmlCharacters(xmlWriter,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[4])));
	simpleXmlEndElement(xmlWriter,NULL,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[5])));
	simpleXmlStartElement(xmlWriter,NULL,buffer);
	simpleXmlCharacters(xmlWriter,"error");
	simpleXmlEndElement(xmlWriter,NULL,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[6])));
	simpleXmlStartElement(xmlWriter,NULL,buffer);
	simpleXmlCharacters(xmlWriter,message);
	simpleXmlEndElement(xmlWriter,NULL,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[2])));
	simpleXmlEndElement(xmlWriter,NULL,buffer);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[0])));
	simpleXmlEndElement(xmlWriter,NULL,buffer);
#else
	simpleXmlStartElement(xmlWriter,NULL,"rpc-error");
	simpleXmlStartElement(xmlWriter,NULL,"error-type");
	simpleXmlCharacters(xmlWriter,error_types[type]);
	simpleXmlEndElement(xmlWriter,NULL,"error-type");
	simpleXmlStartElement(xmlWriter,NULL,"error-tag");
	simpleXmlCharacters(xmlWriter,error_tags[tag]);
	simpleXmlEndElement(xmlWriter,NULL,"error-tag");
	simpleXmlStartElement(xmlWriter,NULL,"error-severity");
	simpleXmlCharacters(xmlWriter,"error");
	simpleXmlEndElement(xmlWriter,NULL,"error-severity");
	simpleXmlStartElement(xmlWriter,NULL,"error-message");
	simpleXmlCharacters(xmlWriter,message);
	simpleXmlEndElement(xmlWriter,NULL,"error-message");
	simpleXmlEndElement(xmlWriter,NULL,"rpc-error");
	simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
#endif
}
/*---------------------------------------------------------------------------*/
static int fd2;
static void
initialize(){
#if CONTIKI_TARGET_AVR_RAVEN
	char buffer[50];
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[7])));
	fd2 = cfs_open(buffer,CFS_WRITE);
	if (fd2>=0){
		strcpy_P(buffer, (char*)pgm_read_word(&(strings[8])));
		//writing default syslog server
		cfs_write(fd2,buffer,strlen(buffer));
		cfs_close(fd2);
	}
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[7])));
	fd2 = cfs_open(buffer,CFS_WRITE+CFS_APPEND);
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[8])));
	if (fd2>=0){
		//writing default ntp server
		cfs_seek(fd2,strlen(buffer),CFS_SEEK_SET);
		strcpy_P(buffer, (char*)pgm_read_word(&(strings[9])));
		cfs_write(fd2,buffer,strlen(buffer));
		//cfs_write(fd2,"<psk>",5);
		strcpy_P(buffer, (char*)pgm_read_word(&(strings[26])));
		cfs_write(fd2,buffer,strlen(buffer));
		strcpy_P(buffer, (char*)pgm_read_word(&(strings[27])));
		cfs_write(fd2,buffer,strlen(buffer));
		strcpy_P(buffer, (char*)pgm_read_word(&(strings[28])));
		cfs_write(fd2,buffer,strlen(buffer));
		//cfs_write(fd2,"</psk>",6);
		strcpy_P(buffer, (char*)pgm_read_word(&(strings[10])));
		cfs_write(fd2,buffer,strlen(buffer)+1);
		cfs_close(fd2);
	}
#else
	fd2 = cfs_open("/config.xml",CFS_WRITE);
	if (fd2>=0){
		//writing default syslog server
		cfs_write(fd2,&"<name>dummy</name>",strlen("<name>dummy</name>"));
		cfs_close(fd2);
	}
	fd2 = cfs_open("/config.xml",CFS_WRITE+CFS_APPEND);
	if (fd2>=0){
		//writing default ntp server
		cfs_seek(fd2,strlen("<name>dummy</name>"),CFS_SEEK_SET);
		cfs_write(fd2,&"<location>here</location>",strlen("<location>here</location>"));
		cfs_write(fd2,&"<psk><psk-identity>thisisme</psk-identity><user-name>someuser</user-name><key>abcdefghijklmnopqrstuvwxyz123456</key></psk>",122);
		cfs_write(fd2,&"<lcd>Hello</lcd>\0",strlen("<lcd>Hello</lcd>")+1);
		cfs_close(fd2);
	}
	
#endif
	memb_init(&pool);
}
/*---------------------------------------------------------------------------*/
static void
getrunning(XmlWriter* xmlWriter){
	char buffer[101]; buffer[100]='\0';
	int pos = 0;
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(buffer, (char*)pgm_read_word(&(strings[7])));
	int elem = cfs_open(buffer,CFS_READ);
#else
	int elem = cfs_open("/config.xml",CFS_READ);
#endif
	do {
		cfs_seek(elem,pos,CFS_SEEK_SET);
		cfs_read(elem, buffer, 100);
		simpleXmlCharacters(xmlWriter,buffer);
		pos+=100;
	} while (strlen(buffer)==100);
		cfs_close(elem);
}
static void
getOperationalState(XmlWriter* xmlWriter){
	/*char string[40];
	int updateTime = getLastTempUpdate();
	int t = getTemperature("C");
	int time = getSysUpTime();
	uip_ipaddr_t* addr = getGlobalIP6Address();
	int sent = getSentPackets();
	int received = getReceivedPackets();
	int fsent = getFailSent();
	int freceived = getFailReceived();
	int sentOctets = getSentOctets();
	int receivedOctets = getReceivedOctets();
	int sentMcast = getSentMcastPackets();
	int rcvdMcast = getReceivedMcastPackets();
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[11])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"update");
#endif
	sprintf(string,"%d",updateTime);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[11])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"update");
#endif
	if (t==-100) sprintf(string,"N/A"); else sprintf(string,"%d",t);
	simpleXmlStartElement(xmlWriter,NULL,"temp");
	simpleXmlAddAttribute(xmlWriter,NULL,"unit","C");
	simpleXmlCharacters(xmlWriter,string);
	simpleXmlEndElement(xmlWriter,NULL,"temp");
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[12])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"sysUpTime");
#endif
	sprintf(string,"%d",time);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[12])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"sysUpTime");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[13])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"globalIP");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	char format[75];
	strcpy_P(format, (char*)pgm_read_word(&(strings[14])));
	sprintf(string,format, ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2], ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5], ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8], ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11], ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14], ((u8_t *)addr)[15]);
	simpleXmlCharacters(xmlWriter,string);
#else
	sprintf(string," %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2], ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5], ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8], ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11], ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14], ((u8_t *)addr)[15]);
	simpleXmlCharacters(xmlWriter,string);
#endif

#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[13])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"globalIP");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[15])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"packetsSent");
#endif
	sprintf(string,"%d",sent);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[15])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"packetsSent");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[16])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"packetsReceived");
#endif
	sprintf(string,"%d",received);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[16])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"packetsReceived");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[17])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"failSent");
#endif
	sprintf(string,"%d",fsent);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[17])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"failSent");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[18])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"failReceived");
#endif
	sprintf(string,"%d",freceived);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[18])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"failReceived");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[19])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"octetsSent");
#endif
	sprintf(string,"%d",sentOctets);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[19])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"octetsSent");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[20])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"octetsReceived");
#endif
	sprintf(string,"%d",receivedOctets);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[20])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"octetsReceived");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[21])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"mcastSent");
#endif
	sprintf(string,"%d",sentMcast);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[21])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"mcastSent");
#endif
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[22])));
	simpleXmlStartElement(xmlWriter,NULL,string);
#else
	simpleXmlStartElement(xmlWriter,NULL,"mcastReceived");
#endif
	sprintf(string,"%d",rcvdMcast);
	simpleXmlCharacters(xmlWriter,string);
#if CONTIKI_TARGET_AVR_RAVEN
	strcpy_P(string, (char*)pgm_read_word(&(strings[22])));
	simpleXmlEndElement(xmlWriter,NULL,string);
#else
	simpleXmlEndElement(xmlWriter,NULL,"mcastReceived");
#endif
*/
}
static int filedescr = 0;

static void
copyConfigHandler(SimpleXmlParser parser, SimpleXmlEvent event, const char* uri, 
const char* szName, const char** szAttribute){
	if (!foundCopyConfig){
#if CONTIKI_TARGET_AVR_RAVEN
		if (event==ADD_SUBTAG && !strcmp_P(szName,copyconfig)){
#else
		if (event==ADD_SUBTAG && !strcmp(szName,"copy-config")){
#endif
			foundCopyConfig=1;
		}
	} else {
		if (event==ADD_SUBTAG){
#if CONTIKI_TARGET_AVR_RAVEN
			if (strcmp_P(szName,target)!=0 && strcmp_P(szName,running)!=0 && strcmp_P(szName,source)!=0
							&& strcmp_P(szName,configstr)!=0 && strcmp_P(szName,contact)!=0 && strcmp_P(szName,location)!=0
							&& strcmp(szName,"name")!=0 && strcmp(szName,"lcd")!=0) {
#else
			if (strcmp(szName,"target")!=0 && strcmp(szName,"running")!=0 && strcmp(szName,"source")!=0
				&& strcmp(szName,"config")!=0 && strcmp(szName,"contact")!=0 && strcmp(szName,"location")!=0 
				&& strcmp(szName,"name")!=0 && strcmp(szName,"lcd")!=0) {
#endif
					compliant=0;
			}
#if CONTIKI_TARGET_AVR_RAVEN
		} else if (event==FINISH_TAG && !strcmp_P(szName,copyconfig)) return;
#else
		} else if (event==FINISH_TAG && !strcmp(szName,"copy-config")) return;
#endif
		else if (event == ADD_ATTRIBUTE) compliant=0;
	}

}

/*----------------------------------------------------------------------------*/
static void
handler(SimpleXmlParser parser, SimpleXmlEvent event, const char* uri, 
const char* szName, const char** szAttribute){
	char sysbuf[50];
	switch(state){
		case HANDLER_ERROR: 
			break;
		case HANDLER_UNINITIALIZED:  /*the original state - expecting a hello message*/
			if (event == ADD_SUBTAG){
#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,hello)){
#else
				if (!strcmp(szName,"hello")){
#endif
					state = HANDLER_HELLO;
				} else {
					state = HANDLER_ERROR;
					uip_close();
					timeout = 1;
				}
			} break;
		case HANDLER_HELLO:	/*processing the hello message*/
			if (event == ADD_SUBTAG){
#if CONTIKI_TARGET_AVR_RAVEN
				if (strcmp_P(szName,capabilities)!=0 && strcmp_P(szName,capability)!=0){
#else
					if (strcmp(szName,"capabilities")!=0 && strcmp(szName,"capability")!=0){
#endif
						state = HANDLER_ERROR;
						uip_close();
						timeout = 1;
					}
				} else if (event == ADD_CONTENT){
#if CONTIKI_TARGET_AVR_RAVEN
					if (!strcmp_P(szName,base1)) netconf1 = 1;
#else
					if (!strcmp(szName,"urn:ietf:params:netconf:base:1.1")) netconf1 = 1;
#endif

				} else if (event == FINISH_TAG){
#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,hello)){
#else
				if (!strcmp(szName,"hello")){
#endif
					state = HANDLER_RCVD_HELLO;
				}
			}
			break;
		case HANDLER_RCVD_HELLO:  /*hello message received, expecting a request*/
			if (event == ADD_SUBTAG){
				if (!strcmp(szName,"rpc")){
					state = HANDLER_RPC;
					rpc=1;
#if CONTIKI_TARGET_AVR_RAVEN
					if (strcmp_P(szAttribute[1],message_id)!=0){
#else
					if (strcmp(szAttribute[1],"message-id")!=0){
#endif
						state=HANDLER_ERROR; 
						uip_close();
						timeout = 1;
						return;
					}
					messageid=strdup(szAttribute[2]);
					replyattr[0]=NULL;
				
					short int tmp = 3;
					while(szAttribute[tmp]!=NULL){
						replyattr[tmp-3]=strdup(szAttribute[tmp]);
						tmp++;
					}
					replyattr[tmp]=NULL;
					tmp = 0;
				}
			}
			break;
		case HANDLER_RPC:	/*rpc message received*/
			if (event == ADD_SUBTAG){
#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,closesession)){
#else
				if (!strcmp(szName, "close-session")){
#endif
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					simpleXmlStartElement(xmlWriter,NULL,"ok");
  					simpleXmlEndElement(xmlWriter,NULL,"ok");
				    simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
					simpleXmlEndDocument(xmlWriter);
					timeout=1;
#if CONTIKI_TARGET_AVR_RAVEN
				} else if (!strcmp_P(szName,getconfig)){
					state=HANDLER_GET_CONFIG;
				} else if (!strcmp_P(szName,copyconfig)){
					state=HANDLER_COPY_CONFIG;
				} else if (!strcmp_P(szName,lock)){
					state=HANDLER_LOCK; locking = 1;
				} else if (!strcmp_P(szName,unlock)){
					state=HANDLER_LOCK; locking = 0;
				} else if (!strcmp_P(szName,get)){
					state=HANDLER_GET;
				} else if (!strcmp_P(szName,killsession)){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,INVALID_VALUE,invalid_tag);
					state = HANDLER_ERROR;
#else
				} else if (!strcmp(szName,"get-config")){
					state=HANDLER_GET_CONFIG;
				} else if (!strcmp(szName,"copy-config")){
					state=HANDLER_COPY_CONFIG;
				} else if (!strcmp(szName,"lock")){
					state=HANDLER_LOCK; locking = 1;
				} else if (!strcmp(szName,"unlock")){
					state=HANDLER_LOCK; locking = 0;
				} else if (!strcmp(szName,"get")){
					state=HANDLER_GET;
				} else if (!strcmp(szName,"kill-session")){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,INVALID_VALUE,invalid_tag);
					state = HANDLER_ERROR;
#endif /*CONTIKI_TARGET_AVR_RAVEN*/
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,APPLICATION,UNKNOWN_ELEMENT,"no"); //not supported
					state = HANDLER_ERROR;
				}
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"rpc")){
					state = HANDLER_RCVD_HELLO;
#if CONTIKI_TARGET_AVR_RAVEN
				} else if (!strcmp_P(szName,closesession)){}
#else
				} else if (!strcmp(szName,"close-session")){}
#endif
				  else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			}
			break;
		case HANDLER_LOCK:
			if (event == ADD_SUBTAG){
#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,target)){
#else
				if (!strcmp(szName,"target")){
#endif
					state = HANDLER_LOCK_TARGET;
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			} else if (event == FINISH_TAG){
				if (locking==1){
#if CONTIKI_TARGET_AVR_RAVEN
					if (!strcmp_P(szName,lock)){
#else
						if (!strcmp(szName,"lock")){
#endif
							state = HANDLER_RPC;
						}
					else {
						rpc_reply(xmlWriter,messageid,(const char**)replyattr);
						rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
						state=HANDLER_ERROR;
					}
				} else if (locking==0){
#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,unlock)){
#else
				if (!strcmp(szName,"unlock")){
#endif
					state = HANDLER_RPC;
				}
					else {
						rpc_reply(xmlWriter,messageid,(const char**)replyattr);
						rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
						state=HANDLER_ERROR;
					}
				}
			}
			break;
		case HANDLER_GET:
			if (event == ADD_SUBTAG){
				if (!strcmp(szName,"filter")){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,APPLICATION,UNKNOWN_ELEMENT,"no"); //filtering not supported
					state = HANDLER_ERROR;
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state=HANDLER_ERROR;
				}
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"get")){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					simpleXmlStartElement(xmlWriter,NULL,"data");
					getrunning(xmlWriter); 
					getOperationalState(xmlWriter);
					simpleXmlEndElement(xmlWriter,NULL,"data");
					simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
					simpleXmlEndDocument(xmlWriter);
					state = HANDLER_RPC;
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state=HANDLER_ERROR;
				}
			} 
			break;
		case HANDLER_LOCK_TARGET:
			if (event == ADD_SUBTAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (strcmp_P(szName,running)!=0){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,"no"); //only running supported
					state = HANDLER_ERROR;
				} else {
				#else
				if (strcmp(szName,"running")!=0){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,"only running supported");
					state = HANDLER_ERROR;
				} else {
				#endif
					if ((locking == 1 && locked == 1) || (locking == 0 && locked==0)){
						rpc_reply(xmlWriter,messageid,(const char**)replyattr);
						if (locking==1)
						rpc_error(xmlWriter,RPC,LOCK_DENIED,"no"); //lock already taken
						else rpc_error(xmlWriter,RPC,LOCK_DENIED,"no"); //lock not held
						state = HANDLER_ERROR;
					} else {
						locked=1-locked;
						rpc_reply(xmlWriter,messageid,(const char**)replyattr);
						simpleXmlStartElement(xmlWriter,NULL,"ok");
  						simpleXmlEndElement(xmlWriter,NULL,"ok");
				        simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
						simpleXmlEndDocument(xmlWriter);
					} 
				}
				
			} else if (event == FINISH_TAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,running)){
				} else 
				if (!strcmp_P(szName,target)!=0){
				#else
				if (!strcmp(szName,"running")){
				} else if (!strcmp(szName,"target")){
				#endif
					state = HANDLER_LOCK;
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state=HANDLER_ERROR;
				}
			}
			break;
		case HANDLER_GET_CONFIG:
			if (event == ADD_SUBTAG){
#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName, source)){
					state = HANDLER_SOURCE;
#else
				if (!strcmp(szName, "source")){
					state = HANDLER_SOURCE;
#endif
				} else if (!strcmp(szName,"filter")){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,APPLICATION,UNKNOWN_ELEMENT,"no"); //filtering not supported
					state = HANDLER_ERROR;
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			} else if (event == FINISH_TAG){
#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,getconfig)){
					state = HANDLER_RPC;
#else
				if (!strcmp(szName,"get-config")){
					state = HANDLER_RPC;
#endif
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			}
			break;
		case HANDLER_SOURCE:
			if (event == ADD_SUBTAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (strcmp_P(szName,running)!=0){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,"no"); //only running supported
					state = HANDLER_ERROR;
				} else if (!strcmp_P(szName,running)){
#else
				if (strcmp(szName,"running")!=0){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,"only running supported");
					state = HANDLER_ERROR;
				} else if (!strcmp(szName,"running")){
#endif
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					simpleXmlStartElement(xmlWriter,NULL,"data");
					getrunning(xmlWriter); 
					simpleXmlEndElement(xmlWriter,NULL,"data");
					simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
					simpleXmlEndDocument(xmlWriter);
				}
			} else if (event == FINISH_TAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,source)){
					state = HANDLER_GET_CONFIG;
				} else if (!strcmp_P(szName,running)){}
				  else {
					xmlWriter->xmlWriteBuffer.nPosition = 0;
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
				#else
				if (!strcmp(szName,"source")){
					state = HANDLER_GET_CONFIG;
				} else if (!strcmp(szName,"running")){}
				  else {
					xmlWriter->xmlWriteBuffer.nPosition = 0;
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
				#endif
			}
			break;
		case HANDLER_COPY_CONFIG:
			if (event == ADD_SUBTAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,target)){
				#else
				if (!strcmp(szName,"target")){
				#endif
					state = HANDLER_COPY_CONFIG_TARGET;
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			} else if (event == FINISH_TAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,copyconfig)){
				#else
				if (!strcmp(szName,"copy-config")){
				#endif
					state = HANDLER_RPC;
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			}
			break;
		case HANDLER_COPY_CONFIG_TARGET:
			if (event == ADD_SUBTAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (strcmp_P(szName,running)!=0){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,"no"); //only running supported
					state = HANDLER_ERROR;
				} 
			} else if (event == FINISH_TAG){
				if (!strcmp_P(szName,running)){} else
				if (!strcmp_P(szName,target)){
				#else
				if (strcmp(szName,"running")!=0){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,"only running supported");
					state = HANDLER_ERROR;
				} 
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"running")){} else
				if (!strcmp(szName,"target")){
				#endif
					state = HANDLER_COPY_CONFIG_SOURCE;
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			}
			break;
		case HANDLER_COPY_CONFIG_SOURCE:
			if (event == ADD_SUBTAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (strcmp_P(szName,source)!=0){
				#else
				if (strcmp(szName,"source")!=0){
				#endif
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
				else state = HANDLER_COPY_CONFIG_RUNNING;
			} else if (event == FINISH_TAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,source)) state = HANDLER_COPY_CONFIG;
				#else
				if (!strcmp(szName,"source")) state = HANDLER_COPY_CONFIG;
				#endif
				else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			}
			break;
		case HANDLER_COPY_CONFIG_RUNNING:
			if (event == ADD_SUBTAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,configstr)){
				#else
				if (!strcmp(szName,"config")){
				#endif
					if (!compliant){
						rpc_reply(xmlWriter,messageid,(const char**)replyattr);
						rpc_error(xmlWriter,RPC,BAD_ELEMENT,"no"); //invalid config
						state = HANDLER_ERROR;
					}else{
						config_offset=0;
						state = HANDLER_COPY_CONFIG_RUNNING_CONFIG;
#if CONTIKI_TARGET_AVR_RAVEN
						char filename[12];
						strcpy_P(filename, (char*)pgm_read_word(&(strings[7])));
						filedescr = cfs_open(filename, CFS_WRITE);
#else
						filedescr = cfs_open("/config.xml",CFS_WRITE);
#endif
						if (filedescr==-1){
							rpc_reply(xmlWriter,messageid,(const char**)replyattr);
							rpc_error(xmlWriter,APPLICATION,OPERATION_FAILED,invalid_tag);
							state = HANDLER_ERROR;
						}
					}
				} else {
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					rpc_error(xmlWriter,RPC,BAD_ELEMENT,invalid_tag);
					state = HANDLER_ERROR;
				}
			}
			break;
		case HANDLER_COPY_CONFIG_RUNNING_CONFIG:

			if (event == ADD_SUBTAG){
				
				if (!strcmp(szName,"lcd")){config = LCD;}
				
				cfs_seek(filedescr,config_offset,CFS_SEEK_SET);

				cfs_write(filedescr,&"< ",2);
				config_offset+=1;
				cfs_seek(filedescr,config_offset,CFS_SEEK_SET);
				if (strlen(szName)==1){
					char dummy[2];
					sprintf(dummy,"%s ",szName);
					cfs_write(filedescr,dummy,2);
				} else {
					cfs_write(filedescr,szName,strlen(szName));
				}
				config_offset+=strlen(szName);
				cfs_seek(filedescr,config_offset,CFS_SEEK_SET);
				cfs_write(filedescr,&"> ",2);
				config_offset+=1;
			} else if (event == ADD_CONTENT){

				cfs_seek(filedescr,config_offset,CFS_SEEK_SET);
				if (strlen(szName)==1){
					char dummy[2];
					sprintf(dummy,"%s ",szName);
					cfs_write(filedescr,dummy,2);
				} else {
					cfs_write(filedescr,szName,strlen(szName));
				}
				config_offset+=strlen(szName);
				if (config==LCD){
					//raven_lcd_show_text((char*)szName);
					config=0;
				}
				
			} else if (event == FINISH_TAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,configstr)){
				#else
				if (!strcmp(szName,"config")){
				#endif
						cfs_seek(filedescr,config_offset,CFS_SEEK_SET);
						cfs_write(filedescr,&"\0 ",2);
						cfs_close(filedescr);

					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					simpleXmlStartElement(xmlWriter,NULL,"ok");
  					simpleXmlEndElement(xmlWriter,NULL,"ok");
				        simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
					simpleXmlEndDocument(xmlWriter);
					state = HANDLER_COPY_CONFIG_SOURCE;
				} else {
					cfs_seek(filedescr,config_offset,CFS_SEEK_SET);
					cfs_write(filedescr,&"</",2);
					config_offset+=2;
					cfs_seek(filedescr,config_offset,CFS_SEEK_SET);
					if (strlen(szName)==1){
						char dummy[2];
						sprintf(dummy,"%s ",szName);
						cfs_write(filedescr,dummy,2);
					} else {
						cfs_write(filedescr,szName,strlen(szName));
					}
					config_offset+=strlen(szName);

					cfs_seek(filedescr,config_offset,CFS_SEEK_SET);
					cfs_write(filedescr,&"> ",2);
					config_offset+=1;

				}
			}
			break;
	}		
}
/*---------------------------------------------------------------------------*/
static void
process_input(char* input, int len){
		int infd;
			while(1){

				if (expected_more!=4){//new message arriving or new chunk to be processed
					if (netconf1){ //netconf 1.1 framing
						if (expected_more==0){
							if (input[input_processed]!='\n') { timeout = 1; return; }
							input_processed+=1;
						}
						if (expected_more == 0 || expected_more == 1){
							if ( len>(input_processed)){
								if( input[input_processed]!='#') { timeout = 1; return; }
								input_processed+=1;
							} else {
								input_processed=0;
								expected_more = 1;
								return;
							}
						}
						if (expected_more == 0 || expected_more == 1 || expected_more == 2){
								if ( len>(input_processed)){
								
									if ( input[input_processed]=='#'){
										if (len>(input_processed+1)){//enough for a closing HASH LF
											if ( input[input_processed+1]!='\n') { timeout = 1; return; }
											else {
												//check if more data after the request, if yes save it in "draft.xml" and come back to it later
												input_processed+=2; int pos = 0;
#if CONTIKI_TARGET_AVR_RAVEN
												char filename[12];
												strcpy_P(filename, (char*)pgm_read_word(&(strings[24])));
												int fd = cfs_open(filename, CFS_WRITE);
#else
												int fd = cfs_open("/draft.xml",CFS_WRITE);
#endif
												has_extra=0;
												char tmp[50];
												while (len>input_processed+50){
													memcpy(tmp, input+input_processed, 50);
													cfs_seek(fd, pos, CFS_SEEK_SET);
													cfs_write(fd, tmp, 50);
													input_processed+=50; pos+=50;
													has_extra=1;
												}
												int extra = len - input_processed;
												if (extra==1){
													char tmp[2];
													tmp[0]= input[input_processed]; tmp[1]='\0';
													cfs_seek(fd, pos, CFS_SEEK_SET);
													cfs_write(fd, tmp, 2);
													has_extra=1; pos++;
												} else if (extra>1){
													char tmp[extra+1];
													memcpy(tmp, input+input_processed, extra);
													tmp[extra]='\0';
													cfs_seek(fd, pos, CFS_SEEK_SET);
													cfs_write(fd, tmp, extra);
													has_extra=1; pos+=extra;
												}	
												cfs_seek(fd, pos, CFS_SEEK_SET);
												cfs_write(fd,"\0\0",2);	
												if (from_draft){
													char tmp[101]; tmp[100]='\0';
													do{
														cfs_close(fd);
#if CONTIKI_TARGET_AVR_RAVEN
														strcpy_P(filename, (char*)pgm_read_word(&(strings[24])));
														fd = cfs_open(filename, CFS_READ);
#else
														fd = cfs_open("/draft.xml",CFS_READ);
#endif
														extra_position+=100;
														cfs_seek(fd,extra_position,CFS_SEEK_SET);
														cfs_read(fd, tmp, 100);
														cfs_close(fd);
#if CONTIKI_TARGET_AVR_RAVEN
														strcpy_P(filename, (char*)pgm_read_word(&(strings[24])));
														fd = cfs_open(filename, CFS_WRITE);
#else
														fd = cfs_open("/draft.xml",CFS_WRITE);
#endif
														cfs_seek(fd,pos,CFS_SEEK_SET);
														if (strlen(tmp)==1){tmp[1]='\0';tmp[2]='\0';
																cfs_write(fd,tmp,2);}
														else{
															cfs_write(fd, tmp, strlen(tmp));
														}
														pos+=strlen(tmp);
													} while (strlen(tmp)==100);
													cfs_seek(fd, pos, CFS_SEEK_SET);
													cfs_write(fd,"\0\0",2);	
													extra_position=0;
												}
												if(has_extra==0)extra_position=0;
												cfs_close(fd);										
												input_processed = 0;
												input_length = 0;
												expected_more=0;
												break;
											}
										} else {//got closing hash but no LF
											input_processed=0;
											expected_more = 4;
											return;
										}
									}
								} else {//got LF HASH
									input_processed=0;
									expected_more = 2;
									return;
								}
						}
						if (expected_more!=6){
							while(len>(input_processed)){
								if ( input[input_processed]!='\n'){
									chunk_size*=10;
									chunk_size+=((int) input[input_processed]-48);
									input_processed++;
								} else break;
							}
							
							if ( input[input_processed]!='\n'){ //didn't get the whole length
								expected_more = 3;
								input_processed = 0;
								return;
							}
							input_processed++;
						}
							
						int remains = len - input_processed;
						int b = chunk_size;
						if (len-input_processed>=chunk_size){//whole chunk plus more
#if CONTIKI_TARGET_AVR_RAVEN
							char filename[12];
							strcpy_P(filename, (char*)pgm_read_word(&(strings[23])));
							infd = cfs_open(filename, CFS_WRITE);
#else
							infd = cfs_open("/input.xml",CFS_WRITE);
#endif
							char buffer[101];
							while ((chunk_size)>100){

								int k;
								for (k=0;k<100;k++){
								buffer[k]= input[input_processed++];
								}	
								buffer[100]='\0';
								cfs_seek(infd,input_length,CFS_SEEK_SET);
								cfs_write(infd,buffer,101);
								input_length+=100;
								chunk_size-=100;
							}
							int k;
							for (k=0;k<chunk_size;k++){
								buffer[k]= input[input_processed++];
							}	
							buffer[chunk_size]='\0';
							cfs_seek(infd,input_length,CFS_SEEK_SET);
							cfs_write(infd,buffer,chunk_size+1);
							input_length+=chunk_size;
							chunk_size=0;
							cfs_close(infd);
							expected_more=0;
							if (remains==b) return;
						} else {//not the whole chunk, write what's there and wait for more
							if (remains>0){
#if CONTIKI_TARGET_AVR_RAVEN
								char filename[12];
								strcpy_P(filename, (char*)pgm_read_word(&(strings[23])));
								infd = cfs_open(filename, CFS_WRITE);
#else
								infd = cfs_open("/input.xml",CFS_WRITE);
#endif
								char buffer[101];
								while (remains>100){

									int k;
									for (k=0;k<100;k++){
										buffer[k]= input[input_processed++];
									}	
									buffer[100]='\0';
									cfs_seek(infd,input_length,CFS_SEEK_SET);
									cfs_write(infd,buffer,101);
									input_length+=100;
									chunk_size-=100;
									remains-=100;
								}
								int k;
								for (k=0;k<remains;k++){
									buffer[k]= input[input_processed++];
								}	
								buffer[remains]='\0';
								cfs_seek(infd,input_length,CFS_SEEK_SET);
								cfs_write(infd,buffer,remains+1);
								input_length+=remains;
								chunk_size-=remains;
								cfs_close(infd);
							}
							expected_more = 6;
							input_processed=0;
							return;
						}
					} else { //a hello message or netconf 1.0 framing
#if CONTIKI_TARGET_AVR_RAVEN
						char filename[12];
						strcpy_P(filename, (char*)pgm_read_word(&(strings[23])));
						infd = cfs_open(filename, CFS_WRITE);
#else
						infd = cfs_open("/input.xml",CFS_WRITE);
#endif
						cfs_seek(infd,input_length,CFS_SEEK_SET);
						cfs_write(infd,input,len);
						cfs_close(infd);
						if (len>6 &&  input[len-1]=='\n'){
							if ( input[len-2]!='>' ||
							     input[len-3]!=']' ||
							     input[len-4]!=']' ||
							     input[len-5]!='>' ||
							     input[len-6]!=']' ||
							     input[len-7]!=']'){
									expected_more = 5;
									input_processed+=len;
									return;
								} else {
									expected_more = 0; input_processed =0; break;
								}
						}
						if (len>5){
							if ( input[len-1]!='>' ||
							     input[len-2]!=']' ||
							     input[len-3]!=']' ||
							     input[len-4]!='>' ||
							     input[len-5]!=']' ||
							     input[len-6]!=']'){
								expected_more = 5;
								input_processed+=len;
								return;
							} else {
								expected_more = 0; input_processed =0; break;
							}
						} else {
							expected_more = 5;
							input_processed+=len;
							return;
						}
					}
				} else if (expected_more == 4) { //got closing hash but no lf
					if ( input[input_processed]!='\n') { timeout = 1; return; }
						else {
							input_processed+=2; int pos = 0;
#if CONTIKI_TARGET_AVR_RAVEN
							char filename[12];
							strcpy_P(filename, (char*)pgm_read_word(&(strings[24])));
							int fd = cfs_open(filename, CFS_WRITE);
#else
							int fd = cfs_open("/draft.xml",CFS_WRITE);
#endif
							has_extra=0;
							char tmp[50];
							while (len>input_processed+50){
								memcpy(tmp, input+input_processed, 50);
								cfs_seek(fd, pos, CFS_SEEK_SET);
								cfs_write(fd, tmp, 50);
								input_processed+=50; pos+=50;
								has_extra=1;
							}
							int extra = len - input_processed;
							if (extra==1){
								char tmp[2];
								tmp[0]= input[input_processed]; tmp[1]='\0';
								cfs_seek(fd, pos, CFS_SEEK_SET);
								cfs_write(fd, tmp, 2);
								has_extra=1; pos++;
							} else if (extra>1){
								char tmp[extra+1];
								memcpy(tmp, input+input_processed, extra);
								tmp[extra]='\0';
								cfs_seek(fd, pos, CFS_SEEK_SET);
								cfs_write(fd, tmp, extra);
								has_extra=1; pos+=extra;
							}	
							cfs_seek(fd, pos, CFS_SEEK_SET);
							cfs_write(fd,"\0\0",2);	
							if (from_draft){
								char tmp[101]; tmp[100]='\0';
								do{
									cfs_close(fd);
#if CONTIKI_TARGET_AVR_RAVEN
									char filename[12];
									strcpy_P(filename, (char*)pgm_read_word(&(strings[24])));
									fd = cfs_open(filename, CFS_READ);
#else
									fd = cfs_open("/draft.xml",CFS_READ);
#endif
									extra_position+=100;
									cfs_seek(fd,extra_position,CFS_SEEK_SET);
									cfs_read(fd, tmp, 100);
									cfs_close(fd);
#if CONTIKI_TARGET_AVR_RAVEN
									strcpy_P(filename, (char*)pgm_read_word(&(strings[24])));
									fd = cfs_open(filename, CFS_WRITE);
#else
									fd = cfs_open("/draft.xml",CFS_WRITE);
#endif
									cfs_seek(fd,pos,CFS_SEEK_SET);
									if (strlen(tmp)==1){tmp[1]='\0';tmp[2]='\0';
											cfs_write(fd,tmp,2);}
									else{
										cfs_write(fd, tmp, strlen(tmp));
									}
									pos+=strlen(tmp);
								} while (strlen(tmp)==100);
								cfs_seek(fd, pos, CFS_SEEK_SET);
								cfs_write(fd,"\0\0",2);	
								extra_position=0;
							}
							if(has_extra==0)extra_position=0;
							cfs_close(fd);										
							input_processed = 0;
							input_length = 0;
							expected_more=0;
							break;
						}
				}
			}

			etimer_restart(&timer);
			xmlWriter = memb_alloc(&pool);

			simpleXmlStartDocument(xmlWriter,"",12000);
			SimpleXmlParser parser = simpleXmlCreateParser("",10000);

			//check if it's a copy-config request, if so check with the data model
			compliant=1; foundCopyConfig=0;

			simpleXmlParse(parser, copyConfigHandler);

			simpleXmlInitializeParser(parser,"",10000);
			simpleXmlParse(parser, handler);

			if(!uip_closed()){
				if (xmlWriter!=NULL){
					if ((char*)xmlWriter->xmlWriteBuffer.sBuffer!=NULL){
						if (strcmp_P(xmlWriter->xmlWriteBuffer.sBuffer,xmlstart)!=0){
					
							outputsize = xmlWriter->xmlWriteBuffer.nPosition;
				
							if (outputsize > strlen_P(xmlstart)){
								more_to_send = 1;
							}
						}
					}	
				}
			}
			state = HANDLER_RCVD_HELLO;
			output[0]=0;
			parts=0;
			simpleXmlDestroyParser(parser);
			if (rpc){
				short int tmp = 0;
				while (replyattr[tmp]!=NULL){
					free(replyattr[tmp]);
					tmp++;
				}
				free(messageid);
				rpc=0;
			}
			memb_free(&pool,xmlWriter);

}		
/*---------------------------------------------------------------------------*/
static void 
process_extra(){
	from_draft=1;
	input_processed=0;
	char extrainput[101];
	memset(extrainput,0,101);
#if CONTIKI_TARGET_AVR_RAVEN
	char filename[12];
	strcpy_P(filename, (char*)pgm_read_word(&(strings[24])));
	int fd = cfs_open(filename, CFS_READ);
#else
	int fd = cfs_open("/draft.xml",CFS_READ);
#endif
		cfs_seek(fd, extra_position, CFS_SEEK_SET);
		cfs_read(fd, extrainput, 100);
		int len = strlen(extrainput);
		if (len!=100){
			char tmp[4]; sprintf(tmp,"%d",len);
			cfs_seek(fd,extra_position,CFS_SEEK_SET);
			cfs_read(fd,extrainput,len);
			extrainput[len]='\0';
			cfs_close(fd);
			has_extra=0;
			from_draft=0;
			process_input(extrainput,len);
			sprintf(tmp,"%d",has_extra);
			extra_position = 0;
			return;
		} else {
			cfs_close(fd); 
			process_input(extrainput,len);
			has_extra=1;
		}
 			extra_position+=100;
	
}
/*---------------------------------------------------------------------------*/
static void
udphandler(process_event_t ev, process_data_t data)
{
	
	if (ev == tcpip_event) {
		if (timeout){
#if TLS
			TLS_Close(connection);
			raven_lcd_show_text("close");
#else
			uip_close();
#endif
			timeout = 0; parts = 0; netconf1 = 0; connected=0; locked=0;etimer_stop(&timer);
		}
		if (uip_closed()){
			connected=0; locked = 0;
		}
#if TLS
	} else if (ev == tls_event) {
		if (tls_connected()){
			connection = (Connection*)data;
#else

		if(uip_connected()){

#endif
			if (!connected)connected=1;
			else {

#if TLS
				TLS_Close(connection);
#else
				uip_close();
#endif
				return;
			}
			etimer_set(&timer,CLOCK_CONF_SECOND*30);
#if CONTIKI_TARGET_AVR_RAVEN
			strcpy_P(output,hello_message);
			strcat(output,"]]>]]>");
#if TLS
			TLS_Write(connection, output, strlen(output));
#else
			uip_send(output,strlen(output));
#endif
#else /* Contiki_target_avr_raven */
			xmlWriter = memb_alloc(&pool);
			simpleXmlStartDocument(xmlWriter,output,1200);
			hello(xmlWriter);
#if TLS
			TLS_Write(connection, output, strlen(output));
#else
			uip_send(output,strlen(output));
#endif
			memb_free(&pool,xmlWriter);
#endif /* CONTIKI_TARGET_AVR_RAVEN */
			output[0]=0;
			state = HANDLER_UNINITIALIZED;
			expected_more = 0;
			input_processed = 0;
			netconf1 = 0;
			has_extra = 0;
			more_to_send=0;
		}
#if TLS
		else if (tls_newdata()){
			process_input(tls_appdata, tls_applen);

#else
 		if(uip_newdata()) {
 			start = clock_time();
			process_input((char*)uip_appdata,uip_datalen());
#endif
		}
	
	} else if (ev == PROCESS_EVENT_TIMER){
		timeout = 1;
	}

}
static void send_output(){
	char outputChunk[110];
	memset(outputChunk, 0, 110);
	int fdout = cfs_open("/output.xml",CFS_READ);
	if(outputsize>100){
		cfs_seek(fdout, position, CFS_SEEK_SET);
		if (netconf1){
			cfs_read(fdout, outputChunk+6,100);
			outputChunk[0]='\n';
			outputChunk[1]='#';
			outputChunk[2]='1';
			outputChunk[3]='0';
			outputChunk[4]='0';
			outputChunk[5]='\n';	
			outputChunk[106] = 0;
		} else {
			cfs_read(fdout, outputChunk,100);
			outputChunk[100] = 0;
		}
#if TLS
		TLS_Write(connection, outputChunk, strlen(outputChunk));
#else
		uip_send(outputChunk,strlen(outputChunk));
#endif
		outputsize-=100;
		position+=100;
		
		more_to_send = 1;
	} else{
		cfs_seek(fdout, position, CFS_SEEK_SET);
		if (outputsize<10) {
			cfs_read(fdout, outputChunk+4, outputsize);
		} else {
			cfs_read(fdout, outputChunk+5, outputsize);
		}
		if (netconf1){
			char f[15];
#if CONTIKI_TARGET_AVR_RAVEN
			strcpy_P(f, (char*)pgm_read_word(&(strings[25])));
#else
			f = "\n#%d\n%s\n##\n\0";
#endif
			if (outputsize<10) sprintf(outputChunk,f,outputsize,outputChunk+4);
			else  sprintf(outputChunk,f,outputsize,outputChunk+5);
		} else {
			sprintf(outputChunk,"%s]]>]]>",outputChunk);
		}
#if TLS
		char tmp[5];
		tmp[5] = 0;
		sprintf(tmp,"%s",outputChunk+5);
		raven_lcd_show_text(tmp);
		TLS_Write(connection, outputChunk, strlen(outputChunk));
#else
		uip_send(outputChunk,strlen(outputChunk));
#endif
		more_to_send = 0;
		outputsize = 0;
		position = 0;


	}
	cfs_close(fdout);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(netconflight_process, ev, data)
{

  PROCESS_BEGIN();

  etimer_set(&timer, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
#if TLS
  TLS_Listen(LISTEN_PORT,1);
#else
  tcp_listen(UIP_HTONS(LISTEN_PORT));
#endif
//create default config here, if no error continue with handling connections
 initialize();
  extern u16_t uip_slen;
  while(1) {

    PROCESS_YIELD();
    if(more_to_send==1){
		if (uip_slen==0) send_output();
    } else if (has_extra){
		process_extra();
	} else {
		udphandler(ev, data);
	}
  }
  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
//LOOK INTO STORING ERROR MESSAGES IN FLASH


///////////////////////////////Hello message//////////////////////////////////
/*
<?xml version='1.0' encoding='UTF-8'?><hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>]]>]]>
*/

///////////////////////////////get-config running/////////////////////////////
/*
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><get-config><source><running></running></source></get-config></rpc>]]>]]>
*/

/////////////////////////////////copy-config//////////////////////////////////
/*
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><copy-config><target><running /></target><source><config><lcd>hello world</lcd><name>Steve</name><location>here</location></config></source></copy-config></rpc>]]>]]>
*/

/////////////////////////////////close-session////////////////////////////////
/*
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><close-session/></rpc>]]>]]>
*/

/*

#163
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><lock><target><running></running></target></lock></rpc>
##

#167
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><unlock><target><running></running></target></unlock></rpc>
##

#125
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><get></get></rpc>
##

#175
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><get-config><source><running></running></source></get-config></rpc>
##

#244
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><copy-config><target><running /></target><source><config><lcd>hello world2</lcd><name>Steve</name></config></source></copy-config></rpc>
##

#243
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><copy-config><target><running /></target><source><config><lfd>hello world</lfd><name>Steve</name></config></source></copy-config></rpc>
##

#175
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><get-config><source><running></running></source></get-config></rpc>
##

#94
<rpc message-id="102" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<close-session/>
</rpc>
##

#4
<rpc
#18
 message-id="102"

#72
xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<close-session/>
</rpc>
##

*/
