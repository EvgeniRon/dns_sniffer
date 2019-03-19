#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

/* Max size of buffer */
#define MAX_PACKET_SIZE 65536

/* Linux socket filter (or BPF) code for filtering out everything but DNS response packets 
 * tcpdump 'port 53 and ((udp and (not udp[10] & 128 = 0)) or \
 * (tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0)))' -dd
 * 
 * udp and (not udp[10] & 128 = 0) - match DNS UDP packets with the QR bit set
 * (tcp[12] & 0xf0) >> 2 - Get TCP header length shift right by 4 , shift left by 2 (multiply by 4)
 *  + 2 - get the third byte of the tcp payload (Third byte of the DNS packet has the QR bit)
 * 
*/

struct sock_filter code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 8, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 36, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 34, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 31, 0, 0x00000035 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 29, 30, 0x00000035 },
    { 0x15, 0, 29, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 27, 0, 0x00000084 },
    { 0x15, 0, 15, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 24, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000035 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 19, 0x00000035 },
    { 0x50, 0, 0, 0x0000001a },
    { 0x54, 0, 0, 0x000000f0 },
    { 0x74, 0, 0, 0x00000002 },
    { 0x4, 0, 0, 0x00000002 },
    { 0xc, 0, 0, 0x00000000 },
    { 0x7, 0, 0, 0x00000000 },
    { 0x50, 0, 0, 0x0000000e },
    { 0x45, 10, 11, 0x00000080 },
    { 0x15, 0, 10, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 8, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000035 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 3, 0x00000035 },
    { 0x50, 0, 0, 0x00000018 },
    { 0x45, 0, 1, 0x00000080 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

struct sock_fprog bpf = {
	.len = sizeof(code)/sizeof(code[0]),
	.filter = code,
};

static int raw_socket;

int init_dns_socket() {
    
    // Open raw socket
    raw_socket = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL));
    if(raw_socket == -1) {
        perror("Socket error");
        return EXIT_FAILURE;
    }

    // Send our compiled LSF filter to kernel
    if(setsockopt(raw_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        perror("Filter error");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void run_sniffer(void (*process_packet)(void *packet, int size)) {
    int size;
    unsigned char packet[MAX_PACKET_SIZE];

    while (1) {
        size = read(raw_socket, &packet, sizeof(packet));
        if (size) {
            process_packet(&packet, size);
        }
    }

    /*
     * Since this program has an infinite loop, the socket "sock" is
     * never explicitly closed. However, all sockets are closed
     * automatically when a process is killed or terminates normally.
     */
 }
    

