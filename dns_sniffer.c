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
#include "socket.h"
#include "dns.h"

#define zero(s) memset(s, 0, sizeof(s))
int arp=0, ipv4=0, ipv6=0, tcp=0, udp=0, http=0, dns=0, ftp=0, smtp=0, num=0;

struct dns_info{
    time_t start;   /* Entry creation time */
    struct in_addr daddr;   /* destination addresses */
    struct in_addr raddr;   /* resolved domain address */
    unsigned short dport;   /* destination port */
    char *domain_name;      /* domain name */
};

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


static void process_tcp_dns(struct tcphdr *hdr) {
    tcp++;

    // printf("Size of TCP header: %d\n", sizeof(struct tcphdr));
	unsigned short src_port = ntohs(hdr->source);
	unsigned short dst_port = ntohs(hdr->dest);

    if (src_port == 53 || dst_port == 53) {
            dns++;
            fprintf(logfile , "Packet type: DNS\n");
            // printf("*******************************\n");
            struct dnshdr *shdr;
            // printf("Size of DNS: %d\n", sizeof(struct dnshdr));
            // int size = sizeof(buffer) - (sizeof(struct dnshdr) + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
            // printf("Size of payload: %d\n", size);
            shdr = (struct dnshdr *)((char *)hdr + sizeof(struct tcphdr));
            fprintf(logfile , "\n");
            fprintf(logfile , "DNS message\n");
            // PrintData(buffer + hdrsize, size-hdrsize);
            print_DNS_Header(shdr);
            fprintf(logfile , "\n");
        }
}

static void process_udp_dns(struct udphdr *hdr) {
    udp++;

    unsigned short src_port;
    unsigned short dst_port;

    src_port = ntohs(hdr->uh_sport);
    dst_port = ntohs(hdr->uh_dport);
    int hdrsize;

    /* sanity check - dns using port 53 */
    if (src_port == 53 || dst_port == 53) {
        dns++;
        fprintf(logfile , "Packet type: DNS\n");

        // printf("*******************************\n");
        struct dnshdr *dns_hdr;
        // printf("Size of DNS: %d\n", sizeof(struct dnshdr));
        // int size = sizeof(buffer) - (sizeof(struct dnshdr) + sizeof(struct tcphdr) + sizeof(struct ether_header) + sizeof(struct iphdr));
        // printf("Size of payload: %d\n", size);

        dns_hdr = (struct dnshdr *)((char *)hdr + sizeof(struct udphdr));
        fprintf(logfile , "\n");
        fprintf(logfile , "DNS message\n");

        print_DNS_Header(dns_hdr);
        parse_dns_response(dns_hdr);

        fprintf(logfile , "\n");
    }
            // print_DNS(shdr);

            // printf("DNS\n");
}

static void process_ipv4_packet(unsigned char* buffer, int size) {
    ipv4++;
	struct iphdr *iph;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;

    iph = (struct iphdr *)(buffer + sizeof(struct ether_header));

    switch (iph->protocol) {
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
            process_tcp_dns(tcphdr);
            break;

        case IPPROTO_UDP:
            udphdr = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
            process_udp_dns(udphdr);
            break;

        default:
            break;
	}
}

static void process_ipv6_packet(unsigned char* buffer, int size) {

    ipv6++;
    struct ip6_hdr *ip6h;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;

    ip6h  = (struct ip6_hdr *)(buffer+ sizeof(struct ether_header));
    printf("Size of ipv6 header: %d\n", sizeof(struct ip6_hdr));

    switch (ntohs(ip6h->ip6_nxt))
    {
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            process_tcp_dns(tcphdr);
            break;

        case IPPROTO_UDP:
            udphdr = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            process_udp_dns(udphdr);
            break;

        default:
            break;
    }
}

static void process_packet(void *buffer, int size) {

    struct ether_header *eth;
    struct ip *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct in_addr addr;

	eth = (struct ether_header*)(buffer);

    ++total;

    //Get the IP Header part of this packet , excluding the ethernet header
    switch (ntohs(eth->ether_type)) //Check the Protocol and do accordingly...
    {
        case ETHERTYPE_IP:  //IPv4 Protocol
            process_ipv4_packet(buffer,size);
            break;

        case ETHERTYPE_IPV6:    //IPv6 Protocol
            process_ipv6_packet(buffer,size);
            break;

        default: //Some Other Protocol - should not get here
            break;
    }
}

int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    /* Initialize the packet capture interface */
    if (init_dns_socket()) return 1;

    logfile=fopen("log.txt","w");
    if(logfile==NULL)
    {
        printf("Unable to create log.txt file.");
    }
    printf("Starting...\n");

    clock_t CPU_time_1 = clock();
    printf("CPU start time is : %d \n", CPU_time_1);

    signal(SIGINT, INThandler);
    run_sniffer(process_packet);

    /* Should'nt get here */
    return 1;
}
