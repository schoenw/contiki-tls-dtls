#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <stdlib.h>
#include "simplexml.h"
//#include "simplexml.c"
#include <string.h>
#include <avr/io.h>
#include "raven-lcd.h"
#include <avr/pgmspace.h>
#include "cfs-coffee.h"
#include "testinit.c"
#include "sys/clock.h"
#include "syslog.h"
#include "sysman.h"
#ifndef DEBUG
#define DEBUG 1
#endif
#if DEBUG
#include <stdio.h>
#ifndef PRINTF
#define PRINTF(...) printf(__VA_ARGS__)
#endif
#endif

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
#if EDIT_CONFIG
#define HANDLER_EDIT_CONFIG 11
#endif /*EDIT_CONFIG*/
#define LCD 1

PROCESS(udp_process_receiver, "netconfd");
AUTOSTART_PROCESSES(&udp_process_receiver);
static struct etimer timer;
static char output[1200];
static char* messageid;
static char* replyattr[10];
static uint8_t rpc=0;
static uint8_t parts = 0;
static uint8_t state = HANDLER_UNINITIALIZED;
static uint8_t timeout = 0;
static volatile unsigned int config_offset=0;
static uint8_t config = 0;
static uint8_t netconf1 = 0;
static XmlWriter* xmlWriter;
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
const char error_rpc_tag[] PROGMEM = "rpc - invalid tag";
const char error_gc_tag[] PROGMEM = "get-config - invalid tag";
#else
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

static void rpc_reply(XmlWriter* xmlWriter, char* messageid, const char** replyattr){
	simpleXmlStartElement(xmlWriter, NULL, "rpc-reply");
	if (strcmp(messageid,"")!=0) simpleXmlAddAttribute(xmlWriter,NULL,"message-id",messageid);
	short int tmp = 0;
	while (replyattr[tmp]!=NULL){	
		if (!strcmp(replyattr[tmp],"")){
			simpleXmlAddAttribute(xmlWriter,NULL,(char*)replyattr[tmp+1],(char*)replyattr[tmp+2]);
		}
		else {simpleXmlAddAttribute(xmlWriter,replyattr[tmp],replyattr[tmp+1],replyattr[tmp+2]);}
		tmp+=3;
	}
}
/*
static void rpc_error(XmlWriter* xmlWriter, PGM_P type, PGM_P tag, PGM_P severity, PGM_P message){
	simpleXmlStartElement(xmlWriter,NULL,"rpc-error");
	simpleXmlStartElement(xmlWriter,NULL,"error-type");
	simpleXmlCharacters(xmlWriter,type);
	simpleXmlEndElement(xmlWriter,NULL,"error-type");
	simpleXmlStartElement(xmlWriter,NULL,"error-tag");
	simpleXmlCharacters(xmlWriter,tag);
	simpleXmlEndElement(xmlWriter,NULL,"error-tag");
	simpleXmlStartElement(xmlWriter,NULL,"error-severity");
	simpleXmlCharacters(xmlWriter,severity);
	simpleXmlEndElement(xmlWriter,NULL,"error-severity");
	simpleXmlStartElement(xmlWriter,NULL,"error-message");
	simpleXmlCharacters(xmlWriter,message);
	simpleXmlEndElement(xmlWriter,NULL,"error-message");
	simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
}*/
/*---------------------------------------------------------------------------*/
static int fd2;
static void
initialize(){
	
	fd2 = cfs_open("/config.xml",CFS_WRITE);
	if (fd2>=0){
		//writing default syslog server
		cfs_write(fd2,&"<syslog>syslog</syslog>",strlen("<syslog>syslog</syslog>"));
		cfs_close(fd2);
	}
	fd2 = cfs_open("/config.xml",CFS_WRITE+CFS_APPEND);
	if (fd2>=0){
		//writing default ntp server
		cfs_seek(fd2,strlen("<syslog>syslog</syslog>"),CFS_SEEK_SET);
		cfs_write(fd2,&"<ntp>ntpdummy</ntp>",strlen("<ntp>ntpdummy</ntp>"));
		cfs_write(fd2,&"<lcd>Hello</lcd>\0",strlen("<lcd>Hello</lcd>")+1);
		cfs_close(fd2);
	}		
	raven_lcd_show_text("hello");
	memb_init(&pool);
}
/*---------------------------------------------------------------------------*/
static void
getrunning(XmlWriter* xmlWriter){
	
	 char buffer[300];
	
	int elem = cfs_open("/config.xml",CFS_READ);
	cfs_read(elem, buffer, 300);
	cfs_close(elem);
	simpleXmlCharacters(xmlWriter,buffer);
			

}
static int filedescr = 0;
/*----------------------------------------------------------------------------*/
static void
handler(SimpleXmlParser parser, SimpleXmlEvent event, const char* uri, 
const char* szName, const char** szAttribute){
	char sysbuf[50];
	switch(state){
		case HANDLER_ERROR: //TODO
			break;
		case HANDLER_UNINITIALIZED:  /*the original state - expecting a hello message*/
			if (event == ADD_SUBTAG){
				if (!strcmp(szName,"hello")){
					state = HANDLER_HELLO;
				} else {
					
					state = HANDLER_ERROR;
					uip_close();
					timeout = 1;
					
				}
			} break;
		case HANDLER_HELLO:	/*processing the hello message*/
			if (event == ADD_SUBTAG){
				if (strcmp(szName,"capabilities")!=0 && strcmp(szName,"capability")!=0){
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
				if (!strcmp(szName,"hello")){
					state = HANDLER_RCVD_HELLO;
				}
			}
			break;
		case HANDLER_RCVD_HELLO:  /*hello message received, expecting a request*/
			if (event == ADD_SUBTAG){
				if (!strcmp(szName,"rpc")){
					state = HANDLER_RPC;
					rpc=1;
					if(strcmp(szAttribute[1],"message-id")!=0){
						state=HANDLER_ERROR; 
						uip_close();
						timeout = 1;
						return;
					}
					printf("ID: %s\n",szAttribute[2]);
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
				if (!strcmp(szName, "close-session")){
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
				#else
				} else if (!strcmp(szName,"get-config")){
					state=HANDLER_GET_CONFIG;
				} else if (!strcmp(szName,"copy-config")){
					state=HANDLER_COPY_CONFIG;
				#endif /*CONTIKI_TARGET_AVR_RAVEN*/
				#if EDIT_CONFIG
				} else if (!strcmp(szName,"edit-config")){
					state=HANDLER_EDIT_CONFIG;
				#endif
				} else {
					state = HANDLER_ERROR;
					timeout = 1;
				}
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"rpc")){
					state = HANDLER_RCVD_HELLO;
				} else if (!strcmp(szName,"close-session")){}
				  else {
					state = HANDLER_ERROR;
					timeout = 1;
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
					state = HANDLER_ERROR;
					timeout = 1;
				} else {
					state = HANDLER_ERROR;
					timeout = 1;
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
					state = HANDLER_ERROR;
					timeout = 1;
				}
			}
			break;
		case HANDLER_SOURCE:
			if (event == ADD_SUBTAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (strcmp_P(szName,running)!=0 && strcmp(szName,candidate)!=0 && strcmp(szName,startup)!=0){
	
					state = HANDLER_ERROR;
					timeout = 1;
				} else if (!strcmp_P(szName,running)){
				#else
				if (strcmp(szName,"running")!=0 && strcmp(szName,"candidate")!=0 && strcmp(szName,"startup")!=0){
	
					state = HANDLER_ERROR;
					timeout = 1;
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
					output[strlen_P(xmlstart)]=0;
					state = HANDLER_ERROR;
					timeout = 1;
				}
				#else
				if (!strcmp(szName,"source")){
					state = HANDLER_GET_CONFIG;
				} else if (!strcmp(szName,"running")){}
				  else {
					output[strlen("<?xml version='1.0' encoding='UTF-8'?>")]=0;
					state = HANDLER_ERROR;
					timeout = 1;
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
					state = HANDLER_ERROR;
					timeout = 1;
				}
			} else if (event == FINISH_TAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,copyconfig)){
				#else
				if (!strcmp(szName,"copy-config")){
				#endif
					state = HANDLER_RPC;
				} else {
					state = HANDLER_ERROR;
					timeout = 1;
				}
			}
			break;
		case HANDLER_COPY_CONFIG_TARGET:
			if (event == ADD_SUBTAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (strcmp_P(szName,running)!=0){
					state = HANDLER_ERROR;
					timeout = 1;
				} 
			} else if (event == FINISH_TAG){
				if (!strcmp_P(szName,running)){} else
				if (!strcmp_P(szName,target)){
				#else
				if (strcmp(szName,"running")!=0){
					state = HANDLER_ERROR;
					timeout = 1;
				} 
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"running")){} else
				if (!strcmp(szName,"target")){
				#endif
					state = HANDLER_COPY_CONFIG_SOURCE;
				} else {
					state = HANDLER_ERROR;
					timeout = 1;
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
					state = HANDLER_ERROR;
					timeout = 1;
				}
				else state = HANDLER_COPY_CONFIG_RUNNING;
			} else if (event == FINISH_TAG){
				#if CONTIKI_TARGET_AVR_RAVEN
				if (!strcmp_P(szName,source)) state = HANDLER_COPY_CONFIG;
				#else
				if (!strcmp(szName,"source")) state = HANDLER_COPY_CONFIG;
				#endif
				else {
					state = HANDLER_ERROR;
					timeout = 1;
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
					config_offset=0;
					state = HANDLER_COPY_CONFIG_RUNNING_CONFIG;
					filedescr = cfs_open("/config.xml",CFS_WRITE);
				if (filedescr==-1){
			//		syslog_msg(sysbuf, FAC_SYSTEM, SEV_INFO, PROCESS_CURRENT(), "didn't open the config");	
			//		syslog_send(sysbuf,NULL);
				}
				} else {
					state = HANDLER_ERROR;
					timeout = 1;
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
					raven_lcd_show_text((char*)szName);
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
	}		
}

/*---------------------------------------------------------------------------*/
static void
udphandler(process_event_t ev, process_data_t data)
{
	char buf[DATA_LEN];
	buf[0]=0;
	if (ev == tcpip_event) {
		if (timeout){uip_close(); timeout = 0; netconf1 = 0; etimer_stop(&timer);}
		if(uip_connected()){
			#if DEBUG
		//	syslog_msg(sysbuf, FAC_SYSTEM, SEV_INFO, PROCESS_CURRENT(), "New connection, sending hello message\n");			
			//syslog_send(sysbuf,NULL);
			#endif

			etimer_set(&timer,CLOCK_CONF_SECOND*30);
			#if CONTIKI_TARGET_AVR_RAVEN
			strcpy_P(output,hello_message);
			
			strcat(output,"]]>]]>");
			uip_send(output,strlen(output));
			#else
			xmlWriter = memb_alloc(&pool);
			simpleXmlStartDocument(xmlWriter,output,1200);
			hello(xmlWriter);
			uip_send(output,strlen(output));
			memb_free(&pool,xmlWriter);
			#endif
			buf[0]=0;
			output[0]=0;
			state = HANDLER_UNINITIALIZED;
		}
 		if(uip_newdata()) {
			if (netconf1){
				if (uip_datalen()==610 && !(
					((char*)uip_appdata)[609]=='\n' &&
					((char*)uip_appdata)[608]=='#' &&
					((char*)uip_appdata)[607]=='#' &&
					((char*)uip_appdata)[606]=='\n')) {
						strcat(output,(char*)uip_appdata);
						parts++;
						output[parts*610+uip_datalen()] = 0;
						return;
				}
			} else {
				if (uip_datalen()==610 && !(
					((char*)uip_appdata)[609]=='>' &&
					((char*)uip_appdata)[608]==']' &&
					((char*)uip_appdata)[607]==']' &&
					((char*)uip_appdata)[606]=='>' &&
					((char*)uip_appdata)[605]==']' &&
					((char*)uip_appdata)[604]==']')) {
						strcat(output,(char*)uip_appdata);
						parts++;
						output[parts*610+uip_datalen()] = 0;
						return;
				}
			}

			etimer_restart(&timer);
      			((char *)uip_appdata)[uip_datalen()] = 0;
			strcat(output,(char*)uip_appdata);
     	
			output[parts*610+uip_datalen()] = 0;
			if (netconf1){
			//decode message in output and copy it to buf
				int i = 0,j=0,k=0;
				while (output[i]!='\0'){
					int chunk_size = 0;
					if (output[i]!='\n' || output[i+1]!='#'){timeout = 1; return;}
					else {
						i+=2;
						if (output[i]=='#' && output[i+1] == '\n'){
							buf[j]='\0';
							break;
						}				
						while (output[i]!='\n'){
							chunk_size*=10;
							chunk_size+=((int)output[i]-48);
							i++;
						}
						if (chunk_size>strlen(output)){timeout = 1; return;}
					}
					i++;
					for (k = 0; k<chunk_size; k++){
						buf[j++] = output[i++];
					}
				}
			} else {			
			strcpy(buf,output);
			}
			xmlWriter = memb_alloc(&pool);
			simpleXmlStartDocument(xmlWriter,output,1200);
			
			SimpleXmlParser parser = simpleXmlCreateParser(buf,parts*610+uip_datalen());

			int error_code=simpleXmlParse(parser, handler);
			if(!uip_closed()){
				if (xmlWriter!=NULL){
					if ((char*)xmlWriter->xmlWriteBuffer.sBuffer!=NULL){
						if (strcmp_P(xmlWriter->xmlWriteBuffer.sBuffer,xmlstart)!=0){
						
						if (netconf1){
						sprintf(buf,"\n#%d\n%s\n##\n",strlen((char*)xmlWriter->xmlWriteBuffer.sBuffer),(char*)xmlWriter->xmlWriteBuffer.sBuffer);
						} else {
						sprintf(buf,"%s]]>]]>",(char*)xmlWriter->xmlWriteBuffer.sBuffer);
						}
						uip_send(buf,strlen(buf));
					//	char* t = getTemperature();
					//	raven_lcd_show_text((const char*)t);
						}
					}	
				}
			}
			output[0]=0;
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
	
	} else if (ev == PROCESS_EVENT_TIMER){
		timeout = 1;
	}
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_process_receiver, ev, data)
{

  PROCESS_BEGIN();

  etimer_set(&timer, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);

  tcp_listen(UIP_HTONS(3000));
  
//create default config here, if no error continue with handling connections
 initialize();
  
  while(1) {
    PROCESS_YIELD();
    udphandler(ev, data);
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
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><copy-config><target><running /></target><source><config><bla>blafjsdddddsfsdfssdsfsdfsf</bla><asd>asdfasdsadasdasdf</asd><blaaaaaa>hhddfldddfgsddsfsdfdda2</blaaaaaa><tmp>hello world</tmp></config></source></copy-config></rpc>]]>]]>
*/

/////////////////////////////////close-session////////////////////////////////
/*
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><close-session/></rpc>]]>]]>
*/
/*

#175
<?xml version='1.0' encoding='UTF-8'?><rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><get-config><source><running></running></source></get-config></rpc>
##

*/
