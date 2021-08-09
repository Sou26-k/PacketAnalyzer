#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

void raw_data_dsp( unsigned char data[], int byte);


int main(int argc, char *argv[]){
	
	int sock;
	int n, recv, byte;
	char buf[1024*128];
 
	struct ifreq ifr;
	struct packet_mreq mreq;
	struct sockaddr_ll sll;
	
	// ソケットの生成
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
		perror("socket");
		exit(1);
	}

	// Bind
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	if(bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0){
		perror("bind");
		exit(1);
	}
	
	while(1){
		// 受信	
		if((byte = read(sock, buf, sizeof(buf))) <= 0){
			perror("read");
			break;
		}
		raw_data_dsp(buf, byte);
	}

	return 0;
}



void raw_data_dsp(unsigned char data[], int byte) {
	
    char sender_mac[24],target_mac[24];//送信元mac,宛先mac
    char sender_ip[12],target_ip[12];//送信元ip,宛先ip


    if(data[12] == 0x08 && data[13] == 0x06){//ARP
        sprintf(sender_mac,"%02x:%02x:%02x:%02x:%02x:%02x",data[22],data[23],data[24],data[25],data[26],data[27]);
        sprintf(target_mac,"%02x:%02x:%02x:%02x:%02x:%02x",data[32],data[33],data[34],data[35],data[36],data[37]);
        sprintf(sender_ip,"%d.%d.%d.%d",data[28],data[29],data[30],data[31]);
        sprintf(target_ip,"%d.%d.%d.%d",data[38],data[39],data[40],data[41]);

        if(data[21] == 0x01){//request
            printf("%s > %s　%d  ARP  Who has %s? Tell %s\n",sender_mac,target_mac,byte,sender_ip,target_ip);
        }else{//reply
            printf("%s > %s　%d  ARP  %s is at %s\n",sender_mac,target_mac,byte,sender_ip,sender_mac);
        }
    }else if(data[12] == 0x08 && data[13] == 0x00){//IPv4

		typedef struct {
			unsigned char headerLength : 4;        
			unsigned char version : 4;             
			unsigned char service;                 
			unsigned short totalLength;            
			unsigned short id;                     
			unsigned char offset2 : 5;             
			unsigned char offset1 : 1;              
			unsigned char dfFlag : 1;               
			unsigned char mfFlag : 1;               
			unsigned char offset3;                 
			unsigned char ttl;                    
			unsigned char protocol;                
			unsigned short checksum;               
			unsigned char srcIP[4];                
			unsigned char destIP[4];              
		} IPHEADER;

		IPHEADER iph;
		int ipHeaderSize,totalLength;
		char buf[128];

		memcpy(&iph,&data[14],sizeof(IPHEADER));

		sprintf(sender_ip,"%d.%d.%d.%d",iph.srcIP[0],iph.srcIP[1],iph.srcIP[2],iph.srcIP[3]);
		sprintf(target_ip,"%d.%d.%d.%d",iph.destIP[0],iph.destIP[1],iph.destIP[2],iph.destIP[3]);


		switch (iph.protocol){
		case 0x01://ICMP
			{
				char type[32];
				unsigned char id[128],seq[128];

				sprintf(id,"%x%x",(unsigned char)data[38],(unsigned char)data[39]);	
				sprintf(seq,"%x%x",(unsigned char)data[40],(unsigned char)data[41]);

				if(data[34] == 0x08){//request
					strcpy(type,"request");
				}else{//reply
					strcpy(type,"reply");
				}

				printf("%s > %s  %d  ICMP  Echo(ping)%s id=%s,seq=%s\n",sender_ip,target_ip,byte,type,id,seq);
			}
			break;
		case 0x06://TCP
			{
				typedef struct{
						unsigned short srcPort;
						unsigned short destPort;
						unsigned char seq[4];
						unsigned char ackNumber[4];
						unsigned char reservation1 : 4;
						unsigned char offset : 4;
						unsigned char fin : 1;
						unsigned char syn : 1;
						unsigned char rst : 1;
						unsigned char psh : 1;
						unsigned char ack : 1;
						unsigned char urg : 1;
						unsigned char reservation2 : 2;
						unsigned short windowSize;
						unsigned short checksum;
						unsigned short urgent;
				}TCPHEADER;

				TCPHEADER tcph;
				unsigned char signal[128];
				unsigned char seq[128],ack[128],status[1024];
				char judge[128],get[128];

				memcpy(&tcph,&data[14+4*iph.headerLength],sizeof(TCPHEADER));

				if(tcph.syn == 1){
					if(tcph.ack == 1){
						strcpy(signal,"SYN ACK");
					}else{
						strcpy(signal,"SYN");
					}
				}else if(tcph.fin == 1){
					strcpy(signal,"FIN");
				}else if(tcph.ack == 1){
					strcpy(signal,"ACK");
				}else{
					strcpy(signal,"Nothing");
				}
				
				int i = 14+4*iph.headerLength+4*tcph.offset;
				
				if((data[i] == 0x48 && data[i+1] == 0x54 && data[i+2] == 0x54 && data[i+3] == 0x50) || (data[i] == 0x47 && data[i+1] == 0x45 && data[i+2] == 0x54)){//HTTP
					
					printf("%s > %s  HTTP  %d  ",sender_ip,target_ip,ntohs(iph.totalLength));
					
					for(;;i++){
						if(data[i]=='\n'){
							break;
						}
						printf("%c",data[i]);
					}
					printf("\n");
				}else{
					if(strcmp(signal,"Nothing") == 0){//制御信号以外
						printf("%s > %s  TCP  %d  %d -> %d  ",sender_ip,target_ip,ntohs(iph.totalLength),ntohs(tcph.srcPort),ntohs(tcph.destPort));

						for(int count = 0;14+4*iph.totalLength != i;i++){
							if(count == 8){
								break;
							}
							printf("%c",data[i]);
							//printf("%x",data[i]);
							count++;
						}
						printf("\n");
					}else{//制御信号
						sprintf(seq,"%x%x%x%x",tcph.seq[0],tcph.seq[1],tcph.seq[2],tcph.seq[3]);
						sprintf(ack,"%x%x%x%x",tcph.ackNumber[0],tcph.ackNumber[1],tcph.ackNumber[2],tcph.ackNumber[3]);

						if(tcph.psh == 1){
							printf("%s > %s  TCP  %d  %d -> %d  [%s] seq=%s ack=%s ",sender_ip,target_ip,ntohs(iph.totalLength),ntohs(tcph.srcPort),ntohs(tcph.destPort),signal,seq,ack);

							
							for(int count = 0;14+4*iph.totalLength != i;i++){
								if(count == 8){
									break;
								}
								printf("%c",data[i]);
								//printf("%x",data[i]);
								count++;
							}
							printf("\n");
						}else{
							printf("%s > %s  TCP  %d  %d -> %d  [%s] seq=%s ack=%s\n",sender_ip,target_ip,ntohs(iph.totalLength),ntohs(tcph.srcPort),ntohs(tcph.destPort),signal,seq,ack);
						}
					}
				}
			}
			break;
		case 0x11://UDP
			{
				typedef struct{
					unsigned short srcPort;
					unsigned short destPort;
					unsigned short length;
					unsigned short checksum;
				} UDPHEADER;

				UDPHEADER udph;
				memcpy(&udph,&data[14+4*iph.headerLength],sizeof(UDPHEADER));

				printf("%s > %s UDP %d %d -> %d Len=%d\n",sender_ip,target_ip,ntohs(udph.length),ntohs(udph.srcPort),ntohs(udph.destPort),(int)(ntohs(udph.length)-8));
			}
			break;
		default://上記以外
			break;
		}
	}else{
		//ARP,IPv4以外のパケット
	}
}