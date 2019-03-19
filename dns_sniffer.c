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


static void process_tcp_dns(struct tcphdr *hdr) {
    // printf("Size of TCP header: %d\n", sizeof(struct tcphdr));
	unsigned short src_port = ntohs(hdr->source);
	unsigned short dst_port = ntohs(hdr->dest);

    // Sanity check
    if (src_port == 53 || dst_port == 53) {
            struct dnshdr *dns_hdr;
            dns_hdr = (struct dnshdr *)((char *)hdr + sizeof(struct tcphdr));
        }
}

static void process_udp_dns(struct udphdr *hdr) {
    unsigned short src_port;
    unsigned short dst_port;
    struct dnshdr *dns_hdr;

    src_port = ntohs(hdr->uh_sport);
    dst_port = ntohs(hdr->uh_dport);

    /* sanity check - dns using port 53 */
    if (src_port == 53 || dst_port == 53) {
        dns_hdr = (struct dnshdr *)((char *)hdr + sizeof(struct udphdr));
        parse_dns_response(dns_hdr);
    }
}

static void process_ipv4_packet(unsigned char* buffer, int size) {
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
    struct ip6_hdr *ip6h;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;

    ip6h  = (struct ip6_hdr *)(buffer+ sizeof(struct ether_header));
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

    // Determine IP version
	eth = (struct ether_header*)(buffer);
    switch (ntohs(eth->ether_type)) {
        case ETHERTYPE_IP:      //IPv4 Protocol
            process_ipv4_packet(buffer,size);
            break;

        case ETHERTYPE_IPV6:    //IPv6 Protocol
            process_ipv6_packet(buffer,size);
            break;

        default: //Some Other Protocol - should not get here
            break;
    }
}

int main() {
    int saddr_size , data_size;
    struct sockaddr saddr;

    // Initialize the packet capture interface
    if (init_dns_socket()) return 1;

    // Run DNS sniffer
    run_sniffer(process_packet);

    // Should'nt get here
    return 1;
}
