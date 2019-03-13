#include<netinet/in.h> 
#include<errno.h>
#include<netdb.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/ip6.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include<time.h>
#include<signal.h>
#define zero(s) memset(s, 0, sizeof(s))
int arp=0, ipv4=0, ipv6=0, tcp=0, udp=0, http=0, dns=0, ftp=0, smtp=0, num=0;

void  INThandler(int sig)
{
     char  c;

     signal(sig, SIG_IGN);
    clock_t CPU_time_2 = clock();
    printf("CPU end time is : %d\n", CPU_time_2);
    printf("TCP: %d\n", tcp);
    printf("UDP: %d\n", udp);
    printf("ipv4: %d\n", ipv4);
    printf("ipv6: %d\n", ipv6);
    printf("ARP: %d\n", arp);
    printf("HTTP: %d\n", http);
    printf("DNS: %d\n", dns);
    printf("FTP: %d\n", ftp);
    printf("SMTP: %d\n", smtp);
    printf("Total: %d\n", num);
          exit(0);
    
}

struct dnshdr
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

struct ipv6_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t traffic_class_1:4, ip_version:4;
    u_int8_t flow_label_1:4, traffic_class_2:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t ip_version:4, traffic_class_1:4;
    u_int8_t traffic_class_2:4, flow_label:4;
#else
#error  "Please fix <bits/endian.h>"
#endif
    u_int16_t flow_label_2;
    u_int16_t payload_length;
    u_int8_t next_header;
    u_int8_t hop_limit;

    u_char src_ipv6[16];
    u_char dst_ipv6[16];
};

FILE *logfile;
struct sockaddr_in source,dest;
// int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j; 
int total=0;
// int num = 0;
char str[50];

void PrintData (unsigned char* data , int Size)
{
    int i , j, num2=0;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            // fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128){
                	// fprintf(logfile, "hello");
                    fprintf(logfile , "%c", (unsigned char)data[j]); //if its a number or alphabet
                }
                 
                else fprintf(logfile , "."); //otherwise print a dot
            }
            // fprintf(logfile , "\n");
        } 
         
        // if(i%16==0) fprintf(logfile , "   ");
        
        // fprintf(logfile , " %02X", (unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            // for(j=0;j<15-i%16;j++) 
            // {
            //   fprintf(logfile , "   "); //extra spaces
            // }
             
            // fprintf(logfile , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                	// fprintf(logfile, "hello");

                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }
             
            // fprintf(logfile ,  "\n" );
        }
    }
}

void print_TCP_Header (struct tcphdr *tcph)
{
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header:\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    
    return;
}
//print_IP_header
void print_IPv4_header (struct iphdr *iph)
{
    unsigned short iphdrlen;
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header:\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));

}

void print_IPV6_header(struct ipv6_header *hdr){
    char src[50], dst[50], stemp[5], dtemp[5];
    int i;

    // hdr = (struct ipv6_header *)(packet + 14);
    zero(src);
    zero(dst);
    for (i = 1; i <= 16; i++) {
        if (i % 2 == 0 && i < 16) {
            sprintf(stemp, "%02x:", hdr->src_ipv6[i - 1]);
            sprintf(dtemp, "%02x:", hdr->dst_ipv6[i - 1]);
        } else {
            sprintf(stemp, "%02x", hdr->src_ipv6[i - 1]);
            sprintf(dtemp, "%02x", hdr->dst_ipv6[i - 1]);
        }
        strcat(src, stemp);
        strcat(dst, dtemp);
    }
    fprintf(logfile , "\nIPV6 Header\n");
    fprintf(logfile , "   |-Source       : %s\n" , src);
    fprintf(logfile , "   |-Destination  : %s\n" , dst);
    fprintf(logfile , "\n");


}

//print UDP header
void print_UDP_header (struct udphdr *udph)
{
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    fprintf(logfile , "\n");
}

void print_DNS_Header (struct dnshdr *dnsh)
{
    fprintf(logfile , "\n");
    fprintf(logfile , "DNS Header:\n");
    fprintf(logfile , "   |-Identification Number      : %u\n",dnsh->id);
    fprintf(logfile , "   |-Recursion Desired          : %u\n",dnsh->rd);
    fprintf(logfile , "   |-Truncated Message          : %u\n",(dnsh->tc));
    fprintf(logfile , "   |-Authoritative Answer       : %u\n",(dnsh->aa));
    fprintf(logfile , "   |-Purpose of message         : %d\n",(unsigned int)dnsh->opcode);
    fprintf(logfile , "   |-Query/Response Flag        : %d\n",(unsigned int)dnsh->qr);
    fprintf(logfile , "   |-Response code              : %d\n",(unsigned int)dnsh->rcode);
    fprintf(logfile , "   |-Checking Disabled          : %d\n",(unsigned int)dnsh->cd);
    fprintf(logfile , "   |-Authenticated data         : %d\n",(unsigned int)dnsh->ad);
    fprintf(logfile , "   |-Recursion available        : %d\n",(unsigned int)dnsh->ra);
    fprintf(logfile , "   |-Number of question entries : %d\n",(dnsh->q_count));
    fprintf(logfile , "   |-Number of answer entries   : %d\n",(dnsh->ans_count));
    fprintf(logfile , "   |-Number of authority entries: %d\n",dnsh->auth_count);
    fprintf(logfile , "   |-Number of resource entries : %d\n",dnsh->add_count);
    fprintf(logfile , "\n");
    return;
}

// void print_IPv6_header(struct ip6_hdr* ip6h)
// {
//     fprintf(logfile , "\nIPv6 Header\n");
//     fprintf(logfile , "   |-Source Address      : %d\n" , ntohs(ip6h->ip6_src));
//     fprintf(logfile , "   |-Destination Address : %d\n" , ntohs(ip6h->ip6_dst));
//     fprintf(logfile , "   |-Version             : 6\n" );
//     //union 
//     //if(  =sizeof(ip6_hdrctl))
//     fprintf(logfile , "   |-Flow Label          : %d\n" , ntohs(ip6h-> ip6_ctlun->ip6_hdrctl->ip6_un1_flow));
//     fprintf(logfile , "   |-Payload Length      : %d\n" , ntohs(ip6h-> ip6_ctlun->ip6_hdrctl->ip6_un1_plen));
//     fprintf(logfile , "   |-Next Header         : %d\n" , ntohs(ip6h-> ip6_ctlun->ip6_hdrctl->ip6_un1_nxt));
//     fprintf(logfile , "   |-Hop Limit           : %d\n" , ntohs(ip6h-> ip6_ctlun->ip6_hdrctl-> ip6_un1_hlim));
//     fprintf(logfile , "\n");
// }


void process_TCP(unsigned char* buffer, int size, int type)
 {
    tcp++;
    struct tcphdr *hdr;
    if(type){
        hdr = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    }
    else{
        hdr = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    }

    // printf("Size of TCP header: %d\n", sizeof(struct tcphdr));


	struct ether_header *eth = (struct ether_header*)(buffer);

    u_short src_port;
	u_short dst_port;
	u_int seq;
	u_int ack;
	src_port = ntohs(hdr->source);
	dst_port = ntohs(hdr->dest);
	seq = ntohl(hdr->seq);
	ack = ntohl(hdr->ack);
	int hdrsize;
    
    if (src_port == 53 || dst_port == 53)  //DNS protocol
		// process_DNS inter,size);
        {
            dns++;
                        fprintf(logfile , "Packet type: DNS\n");
            // printf("*******************************\n");
            struct dnshdr *shdr;
            // printf("Size of DNS: %d\n", sizeof(struct dnshdr));
            // int size = sizeof(buffer) - (sizeof(struct dnshdr) + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
            // printf("Size of payload: %d\n", size);
            if(type){  
            shdr = (struct dnshdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
                        hdrsize= sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr);
            fprintf(logfile , "\n");
            fprintf(logfile , "DNS message\n");
            // PrintData(buffer + hdrsize, size-hdrsize);
            print_DNS_Header(shdr); 
            fprintf(logfile , "\n");

            }
            else{
            shdr = (struct dnshdr *)(buffer + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
                        hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
            fprintf(logfile , "\n");
            fprintf(logfile , "DNS message\n");
            // PrintData(buffer + hdrsize, size-hdrsize);
            print_DNS_Header(shdr); 
            fprintf(logfile , "\n");

            }
            // print_DNS(shdr);  
            
            // printf("DNS\n");                    
        }
}

void process_UDP(unsigned char* buffer, int size, int type){
    udp++;
   struct udphdr *hdr;

    if(type){
        hdr = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    }
    else{
        hdr = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    }

    u_short src_port;
    u_short dst_port;
   
    src_port = ntohs(hdr->source);
    dst_port = ntohs(hdr->dest);
    int hdrsize;

    if (src_port == 53 || dst_port == 53) {
            dns++;
            fprintf(logfile , "Packet type: DNS\n");

            // printf("*******************************\n");
            struct dnshdr *shdr;
            // printf("Size of DNS: %d\n", sizeof(struct dnshdr));
            // int size = sizeof(buffer) - (sizeof(struct dnshdr) + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
            // printf("Size of payload: %d\n", size);
            
            if(type){  
            shdr = (struct dnshdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
                        hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr);
            fprintf(logfile , "\n");
            fprintf(logfile , "DNS message\n");
            // PrintData(buffer + hdrsize, size-hdrsize);
            print_DNS_Header(shdr); 
            fprintf(logfile , "\n");

            }
            else{
            shdr = (struct dnshdr *)(buffer + sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            hdrsize= sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct ip6_hdr);
            fprintf(logfile , "\n");
            fprintf(logfile , "DNS message\n");
            // PrintData(buffer + hdrsize, size-hdrsize);
            print_DNS_Header(shdr); 
            fprintf(logfile , "\n");

            }
            // print_DNS(shdr);  
                                
            // printf("DNS\n");                    
        }
}

void process_IPv4(unsigned char* buffer, int size)
{
    ipv4++;
	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));

    switch (iph->protocol) {
	case 6:
		process_TCP(buffer,size,1);
		break;

	case 17:
		process_UDP(buffer,size,1);
		break;

	default:
       fprintf(logfile , "Packet type: IPv4\n");
		print_IPv4_header(iph);
		break;
	}
}

void process_IPv6(unsigned char* buffer, int size)
{

    ipv6++;
    struct ipv6_header *ip6h = (struct ipv6_header *)(buffer+ sizeof(struct ether_header));
    struct ether_header *eth = (struct ether_header*)(buffer);
    printf("Size of ipv6 header: %d\n", sizeof(struct ipv6_header));

    switch (ntohs(ip6h->next_header))
    {
        case 6 :
            // printf("This is TCP inside IPv6\n");
            process_TCP(buffer,size,0);

            break;
        case 17:
            // printf("This is UDP inside TPv6\n");
            process_UDP(buffer,size,0);

            break;
        default:
            break;
    }
}

void process_Ether(unsigned char* buffer, int size) {
	struct ether_header *eth = (struct ether_header*)(buffer);
    //Get the IP Header part of this packet , excluding the ethernet header
    ++total;
    // printf("Size of ether header: %d\n", sizeof(struct ether_header));
    switch (ntohs(eth->ether_type)) //Check the Protocol and do accordingly...
    {
        case 0x0800:  //IPv4 Protocol
            process_IPv4(buffer,size);
        	// printf("IPv4\n");
            // printEther(eth);

            break;
         
        case 0x86dd:  //IPv6 Protocol
            process_IPv6(buffer,size);
           	// printf("IPv6\n");
            // printEther(eth);

            break;
         
        default: //Some Other Protocol
            break;
    }
}
//tcpdump -i any 'port 53 and ((udp and (not udp[10] & 128 = 0)) or (tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0)))' -dd
int main()'
{'
    int saddr_size , data_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
     
    logfile=fopen("log.txt","w");
    if(logfile==NULL) 
    {
        printf("Unable to create log.txt file.");
    }
    printf("Starting...\n");
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    clock_t CPU_time_1 = clock();
    printf("CPU start time is : %d \n", CPU_time_1);
    signal(SIGINT, INThandler);
    while(1)
    {

        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        num++;
        // sprintf(str, " %02X", buffer);
        // puts(str);
        // PrintData(buffer, data_size);
            fprintf(logfile , "\nPacket number %d\n", num);

      // printf("Size of packet: %d\n", data_size);


        process_Ether(buffer , data_size);
        // char ch;
       	// if(getchar())
        // if(ch=='Q')// Q for Quit
             // exit(0);
    }

    close(sock_raw);
    printf("Finished");
    return 0;
}
