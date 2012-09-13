#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <stdlib.h>
#include "simplexml.h"
#include <string.h>
#include "sys/clock.h"
#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2], ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5], ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8], ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11], ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14], ((u8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF(" %02x:%02x:%02x:%02x:%02x:%02x ",(lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3],(lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

#define UDP_IP_BUF   ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

#define DATA_LEN 1200
#define HANDLER_ERROR -1
#define HANDLER_UNINITIALIZED 0
#define HANDLER_HELLO 1
#define HANDLER_RPC 2
#define HANDLER_GET_CONFIG 3
#define HANDLER_SOURCE 4
//static struct uip_conn *conn;
static struct psock ps;
PROCESS(udp_process_receiver, "UPD test receiver");
AUTOSTART_PROCESSES(&udp_process_receiver);
static struct etimer timer;
static char output[1280];
static char* messageid;
static char* replyattr[15];
static int rpc=0;
static int parts = 0;
static int state = HANDLER_UNINITIALIZED;
static XmlWriter* xmlWriter;
static char* running = "<users><user><id>1</id><name>VP</name></user></users>";
static void rpc_reply(XmlWriter* xmlWriter, char* messageid, const char** replyattr){
	simpleXmlStartElement(xmlWriter, NULL, "rpc-reply");
	simpleXmlAddAttribute(xmlWriter,NULL,"message-id",messageid);
	int tmp = 0;
	while (replyattr[tmp]!=NULL){	
		if (!strcmp(replyattr[tmp],"")){
			simpleXmlAddAttribute(xmlWriter,NULL,(char*)replyattr[tmp+1],(char*)replyattr[tmp+2]);
		}
		else {simpleXmlAddAttribute(xmlWriter,replyattr[tmp],replyattr[tmp+1],replyattr[tmp+2]);}
		tmp+=3;
	}
      /*simpleXmlStartElement(xmlWriter,NULL,"ok");
      simpleXmlEndElement(xmlWriter,NULL,"ok");
      simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
      simpleXmlEndDocument(xmlWriter);*/
}
static void hello(XmlWriter* xmlWriter){
	simpleXmlStartElement(xmlWriter,NULL,"hello");
	simpleXmlAddAttribute(xmlWriter,NULL,"xmlns","urn:ietf:params:xml:ns:netconf:base:1.0");
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

/*---------------------------------------------------------------------------*/
static void
handler(SimpleXmlParser parser, SimpleXmlEvent event, const char* uri, 
const char* szName, const char** szAttribute){
	switch(state){
		case HANDLER_ERROR: break;
		case HANDLER_UNINITIALIZED:
			if (event == ADD_SUBTAG){
				if (!strcmp(szName,"hello")){
					state = HANDLER_HELLO;
				
				} else if (!strcmp(szName,"rpc")){
					state = HANDLER_RPC;
					rpc=1;
					if(strcmp(szAttribute[1],"message-id")!=0){
					//send reply-error
						printf("error!\n");
						state=HANDLER_ERROR; 
						return;
					}
					printf("ID: %s\n",szAttribute[2]);
					messageid=strdup(szAttribute[2]);
					replyattr[0]=NULL;
				
					int tmp = 3;
					while(szAttribute[tmp]!=NULL){
						replyattr[tmp-3]=strdup(szAttribute[tmp]);
						tmp++;
					}
					replyattr[tmp]=NULL;
					tmp = 0;
				}
			} break;
		case HANDLER_HELLO:
			if (event == ADD_SUBTAG){
				if (strcmp(szName,"capabilities")!=0 && strcmp(szName,"capability")!=0){
					printf("invalid tag %s, closing the connection\n",szName);
					state = HANDLER_ERROR;				
					uip_close();
				}
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"hello")){
					state = HANDLER_UNINITIALIZED;
				}
			}
			break;
		case HANDLER_RPC:
			if (event == ADD_SUBTAG){
				if (!strcmp(szName, "close-session")){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					simpleXmlStartElement(xmlWriter,NULL,"ok");
  					simpleXmlEndElement(xmlWriter,NULL,"ok");
				        simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
					simpleXmlEndDocument(xmlWriter);
					//uip_close();
				} else if (!strcmp(szName,"get-config")){
					state=HANDLER_GET_CONFIG;
				}
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"rpc")){
					state = HANDLER_UNINITIALIZED;
				}
			}
			break;
		case HANDLER_GET_CONFIG:
			if (event == ADD_SUBTAG){
				if (!strcmp(szName, "source")){
					state = HANDLER_SOURCE;
				} else if (!strcmp(szName,"filter")){

				} else {
					printf("invalid tag %s, closing the connection\n",szName);
					state = HANDLER_ERROR;				
					uip_close();
				}
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"get-config")){
					state = HANDLER_RPC;
				}
			}
			break;
		case HANDLER_SOURCE:
			if (event == ADD_SUBTAG){
				if (strcmp(szName,"running")!=0 && strcmp(szName,"candidate")!=0 && strcmp(szName,"startup")!=0){
					printf("invalid datastore %s, closing the connection\n",szName);
					state = HANDLER_ERROR;				
					uip_close();
				} else if (!strcmp(szName,"running")){
					rpc_reply(xmlWriter,messageid,(const char**)replyattr);
					simpleXmlStartElement(xmlWriter,NULL,"data");
					simpleXmlCharacters(xmlWriter,running);
					simpleXmlEndElement(xmlWriter,NULL,"data");
					simpleXmlEndElement(xmlWriter,NULL,"rpc-reply");
					simpleXmlEndDocument(xmlWriter);
				}
			} else if (event == FINISH_TAG){
				if (!strcmp(szName,"source")){
					state = HANDLER_GET_CONFIG;
				}
			}
			break;
	}
}

/*---------------------------------------------------------------------------*/
static 
PT_THREAD(handle_connection(struct psock *p, process_event_t ev, process_data_t data)
{
	PSOCK_BEGIN(p);
	char buf[DATA_LEN];
	buf[0]=0;
  	
	if (ev == tcpip_event) {
		
 		if(uip_newdata()) {
			
			printf("length: %d\n",uip_datalen());
			if (uip_datalen()==610){
				strcat(output,(char*)uip_appdata);
				parts++;
				output[parts*610+uip_datalen()] = 0;
				return;
			}
			etimer_restart(&timer);
      			((char *)uip_appdata)[uip_datalen()] = 0;
			strcat(output,(char*)uip_appdata);
     	
			output[parts*610+uip_datalen()] = 0;
			strcpy(buf,output);
			xmlWriter = malloc(sizeof(XmlWriter));
			simpleXmlStartDocument(xmlWriter,output,1000);
			printf("Received: '%s'\n", buf);
			//PRINT6ADDR(&UDP_IP_BUF->srcipaddr);
			//PRINTF("\n");
			SimpleXmlParser parser = simpleXmlCreateParser(buf,parts*610+uip_datalen());
			int error_code=simpleXmlParse(parser, handler);
			if(!uip_closed()){
				printf("error code: %d\n", error_code);
				if (xmlWriter!=NULL){
				if ((char*)xmlWriter->xmlWriteBuffer.sBuffer!=NULL){
					if (strcmp(xmlWriter->xmlWriteBuffer.sBuffer,"<?xml version='1.0' encoding='UTF-8'?>")!=0){
					PRINTF("Responding with message: ");
					sprintf(buf,"%s]]>]]>",(char*)xmlWriter->xmlWriteBuffer.sBuffer);
					PRINTF("%s\n", buf);
					output[0]=0;
					uip_send(buf,strlen(buf));
							
					}
				}}
			}
			simpleXmlDestroyParser(parser);
			if (rpc){
				int tmp = 0;
				while (replyattr[tmp]!=NULL){
					free(replyattr[tmp]);
					tmp++;
				}
				free(messageid);
				rpc=0;
			}
			free(xmlWriter);
		}
	} else if (ev == PROCESS_EVENT_TIMER){
		printf("timed out!\n");
		PSOCK_CLOSE(p);
	}
	PSOCK_END(p);
	
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_process_receiver, ev, data)
{
  

  PROCESS_BEGIN();
  PRINTF("Process test TCP listener started\n");

  etimer_set(&timer, CLOCK_CONF_SECOND*3);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);

  tcp_listen(UIP_HTONS(3000));
  PRINTF("Listening on TCP port 3000\n");
//create default config here, if no error continue with handling connections
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev==tcpip_event);
	if (uip_connected()){
		PSOCK_INIT(&ps, output, sizeof(output));
		printf("new connection, sending hello message\n");
//			printf("time: %u\n",(uint16_t)clock_seconds());
		etimer_set(&timer,CLOCK_CONF_SECOND*5);
		xmlWriter = malloc(sizeof(XmlWriter));
		simpleXmlStartDocument(xmlWriter,output,1000);
		hello(xmlWriter);
		sprintf(buf,"%s]]>]]>",(char*)xmlWriter->xmlWriteBuffer.sBuffer);
		uip_send(buf,strlen(buf));
		free(xmlWriter);
		buf[0]=0;
		output[0]=0;
	
		while(!(uip_aborted() || uip_closed() || uip_timedout())) {
			PROCESS_WAIT_EVENT_UNTIL(ev == tcpip_event);
			 handle_connection(&ps,ev, data);
		}
	}
   
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
