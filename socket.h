#ifndef SOCKET_H
#define SOCKET_H

int init_dns_socket();

void run_sniffer(void (*process_packet)(void *packet, int size));

#endif /* SOCKET_H */
