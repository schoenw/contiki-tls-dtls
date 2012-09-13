#include "sysman/sysman.h"
#include "sysman-arch.h"
#include "cfs-coffee.h"
#include <stdlib.h>
#include <float.h>
#include <string.h>
#include <stdio.h>
#include <avr/io.h>
#include <avr/pgmspace.h>
#define READ 1
#define NOREAD 0

static char answer[100];
static uip_ipaddr_t* locaddr = NULL;
char *mystrdup(const char *str)
{
    int n = strlen(str) + 1;
    char *dup = malloc(n);
    if(dup)
    {
        strcpy(dup, str);
    }
    return dup;
}
double myatof(char* value){
	double answer = 0;
	int i = 0;
	for (i = 0; i < strlen(value); i++){
		if ((int)value[i]==46) break;
		answer*=10;
		answer+=((int)value[i]-48);
	}
	int power = 1;
	for (; i<strlen(value); i++){
		answer+=((int)value[i]-48)/power;
		power*=10;
	}
	return answer;
}
int hexToint(char value){
	if ((int)value<58 && (int)value>47) return (int)value-48;
	else if ((int)value<103 && (int)value>96) return (int)value-87;
	else if ((int)value<71 && (int)value>64) return (int)value-55;
	else return -1;
}
uip_ipaddr_t* charToipaddr(char* value, uip_ipaddr_t* addr){
	if(addr==NULL){
		return NULL;
	}
	int i = 0; int elem = 0;
	while (value[i]!='\0'){
		char part[4]; int j = 0; 
		for (j=0;j<4;j++)part[j]='\0'; 
		j=0;
		while(value[i]!=':' && value[i]!='\0'){
			part[j]=value[i];
			i++; j++;
		}
		if (strlen(part)==4){
			addr->u8[elem++]=hexToint(part[0])*16+hexToint(part[1]);
			addr->u8[elem++]=hexToint(part[2])*16+hexToint(part[3]);
		} else if (strlen(part)==3){
			addr->u8[elem++]=hexToint(part[0]);
			addr->u8[elem++]=hexToint(part[1])*16+hexToint(part[2]);
		} else if (strlen(part)==2){
			addr->u8[elem++]=0;
			addr->u8[elem++]=hexToint(part[0])*16+hexToint(part[1]);
		} else if (strlen(part)==1){
			addr->u8[elem++]=0;
			addr->u8[elem++]=hexToint(part[0]);
		} else {
			int count=0;
			for(j=0;j<strlen(value);j++) if(value[j]==':')count++;
			count=8-count;
			if (value[0]==':')count++;
			if (value[strlen(value)-1]==':')count++;
			for (j=0; j<count; j++){
				addr->u8[elem++]=0;
				addr->u8[elem++]=0;
			}
		}
		i++;
	}
	char tmp[5];
	sprintf(tmp,"%d",addr->u8[15]);
	
	return addr;
	
}

char* getFromConfig(char* value){
	int fd;
	fd = cfs_open("/config.xml",CFS_READ);
	memset(answer,0,100);
	int i = 0,j=0,k=0;
	uint8_t check = 1;
	if (fd!=-1){
		char config[128];
		int read;
		read = cfs_read(fd, config, 128);
		cfs_close(fd);
		while (config[i]!='\0'){
			if (config[i]=='<'){
				i++;
				for (j=0;j<strlen(value);j++){
					if (config[i]!=value[j]){
						check = 0;
						break;
					}
					i++;
				}	
				if (check && config[i]=='>'){
					i++;
					j=0;
					while (config[i]!='<' && j<100){
						answer[j++]=config[i++];
					} break;
				}		
			} 
			if (config[i]=='>'){
				//if (config[i+1]=='\0') break;
				k+=i;
				cfs_open("/config.xml",CFS_READ);
				cfs_seek(fd,++k,CFS_SEEK_SET);
				memset(config,0,128);
				cfs_read(fd,config,128);
				cfs_close(fd);
				check = 1;
				i=-1;
			}
			i++;
		}
		return answer;
	} else return "-";
}

int getTemperature(char* unit){
		lastTempUpdate = getSysUpTime();
		return GET_TEMPERATURE(unit);
}

int getLastTempUpdate(){
	return lastTempUpdate;
}
char* getLCDMessage(){
	char* output;
	char* fromConfig = getFromConfig("lcd");
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return GET_LCDMESSAGE();
	} 
	output = mystrdup(answer);
	return output;
}

int getSysUpTime(){

	return GET_SYSUPTIME();

}

char* getSysContact(){
	char* output;
	char* fromConfig = getFromConfig("contact");
	
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return GET_SYSCONTACT();
	} 
	output = mystrdup(answer);
	return output;
}

char* getSysDesc(){
	char* output;
	char* fromConfig = getFromConfig("desc");
	
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return CONTIKI_VERSION_STRING;
	} 
	output = mystrdup(answer);
	return output;
}

char* getSysLocation(){
	char* output;
	char* fromConfig = getFromConfig("location");
	
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return "";
	} 
	output = mystrdup(answer);
	return output;
}

char* getSysName(){
	char* output;
	char* fromConfig = getFromConfig("name");
	
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return GET_SYSNAME();
	} 
	output = mystrdup(answer);
	return output;
}

char* getIfName(){
	char* output;
	char* fromConfig = getFromConfig("ifname");
	
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return GET_IFNAME();
	} 
	output = mystrdup(answer);
	return output;
}


uip_ipaddr_t* getGlobalIP6Address(){

	return GET_GLOBALIP6ADDRESS();

}

uip_ipaddr_t* getDefaultRouter(){
	char* output;
	char* fromConfig = getFromConfig("router");
	
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return GET_DEFAULTROUTER();
	} 
	
	output = mystrdup(answer);
	locaddr = (uip_ipaddr_t*)malloc(sizeof(uip_ipaddr_t));
	return charToipaddr(output, locaddr);
}

uip_ipaddr_t* getSyslogServer(){
	char* output;
	char* fromConfig = getFromConfig("syslog");
	
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return GET_DEFAULTROUTER();
	} 
	output = mystrdup(answer);
	locaddr = (uip_ipaddr_t*)malloc(sizeof(uip_ipaddr_t));
	return charToipaddr(output, locaddr);
}

uip_ipaddr_t* getNTPServer(){
	char* output;
	char* fromConfig = getFromConfig("ntp");
	
	if (!strcmp(fromConfig,"-") || answer[0]==0){
		return GET_DEFAULTROUTER();
	} 
	output = mystrdup(answer);
	locaddr = (uip_ipaddr_t*)malloc(sizeof(uip_ipaddr_t));
	return charToipaddr(output, locaddr);
}

int getSentPackets(){
	return GET_SENTPACKETS();
}

int getReceivedPackets(){
	return GET_RECEIVEDPACKETS();
}

int getFailSent(){
	return GET_FAILSENT();
}

int getFailReceived(){
	return GET_FAILRECEIVED();
}

int getSentOctets(){
	return GET_SENTOCTETS();
}

int getReceivedOctets(){
	return GET_RECEIVEDOCTETS();
}

int getSentMcastPackets(){
	return GET_SENTMCASTPACKETS();
}

int getReceivedMcastPackets(){
	return GET_RECEIVEDMCASTPACKETS();
}

void freeMemory(){
	if (locaddr) free(locaddr);
}
