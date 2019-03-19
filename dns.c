#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include<netinet/in.h>
#include "dns.h"

/*
 * Parse the name field in DNS Resource Record
 * Converts a compressed domain name to the human-readable form 
*/
static int parse_name(char *dns_packet, char *seek_ptr, char *name, unsigned int name_max_length) {
	int slen;			// Length of current segment
	int clen = 0;		// Total length of compressed name
	int jumped = 0;		// Set if jumped to pointer
	int nseg = 0;		// Total number of label in name

	for(;;) {
		slen = *seek_ptr++;				// Length of this segment
		
		if (!jumped) {
			clen++;
		}
		
		// Compressed pointer
		if ((slen & 0xc0) == 0xc0) {
			seek_ptr = &dns_packet[((slen & 0x3f)<<8) + *seek_ptr];	// Follow compressed poimter
			if(!jumped) {
				clen++;
			}	
			jumped = 1;			
			slen = *seek_ptr++;
		}

		if (slen == 0) {
			break;	// zero length == all done
		}			

		if (!jumped) {
			clen += slen;
		} 

		if((name_max_length -= slen+1) < 0)
		{
			return 0;
		}
		
		while (slen-- != 0) {
			*name++ = *seek_ptr++;
		}

		*name++ = '.';

		nseg++;
	}

	if(nseg == 0) {
		*name++ = '.';				// Root name; represent as single dot
	}	
	else {
		--name;
	} 

	*name = '\0';

	return clen; // Length of compressed message
}

static void parse_query(char *dns_packet, char *seek_ptr, query_t *query) {
	
	char qname[MAX_NAME_LEN];

	query->qname_length = parse_name(dns_packet,seek_ptr, &qname[0], sizeof(qname));
	query->qname = malloc(sizeof(char) * query->qname_length);
	memcpy(query->qname, &qname, query->qname_length);

	// Point to the QTYPE and QCLASS fields
    query->question = (question_const_fields_t *)(seek_ptr + query->qname_length);
	
	return;
}

static void parse_answer(char *dns_packet, char *seek_ptr, resource_record_t *answer) {
	char name[MAX_NAME_LEN];
	char str[INET6_ADDRSTRLEN];
	int type;

	answer->name_length = parse_name(dns_packet, seek_ptr, &name[0], sizeof(name));
	answer->name = malloc(sizeof(char) * answer->name_length);
	memcpy(answer->name, &name, answer->name_length);

	seek_ptr = seek_ptr + answer->name_length;
	answer->resource = (rr_const_fields_t *)seek_ptr;

	seek_ptr += 2; // Skip Type field (2 bytes size)
	seek_ptr += 2; // Skip Class field (2 bytes size)
	seek_ptr += 4; // Skip TTL field (4 bytes)
	seek_ptr += 2; // Skip RDLENGTH field (2 bytes)
	answer->rdata = seek_ptr;

	type = ntohs(answer->resource->type);
	switch(type) {
		case TYPE_A:
			printf("RRs : TYPE_A (IPv4) = %s\n", inet_ntop(AF_INET, answer->rdata, str, INET_ADDRSTRLEN));
			break;
		case TYPE_AAAA:
			printf("RRs : TYPE_AAAA (IPv6) %s\n", inet_ntop(AF_INET6, answer->rdata, str, INET6_ADDRSTRLEN));
			break;
	}

}
/*
static void parse_answer(char *dns_packet, char *seek_ptr, resource_record_t *answer) {
	
	
	
	
	resource_record_t answer;
	void *ip_buffer;
	char str[INET6_ADDRSTRLEN];
	
	answer.name = name;
	// Get the resolved IP from the answer
	for (int i = 0; i < num_answers; i++) {
		// Point to the constant sized fields
		if(*(answer.name) >= COMPRESSED_PTR) {
			answer.resource = (rr_const_fields_t *)(answer.name + sizeof(short));
		} 
		else {
			answer.resource = (rr_const_fields_t *)(answer.name + strlen((const char*)answer.name) + 1);
		}

		ip_buffer = (void *)((char *)answer.resource + sizeof(rr_const_fields_t));
		
		if(ntohs(answer.resource->type == TYPE_A)) {
			inet_ntop(AF_INET, ip_buffer, str, INET_ADDRSTRLEN);
			printf("resolved ip: %s\n", str);
		}
		else if(ntohs(answer.resource->type == TYPE_AAAA)) {
			inet_ntop(AF_INET6, ip_buffer, str, INET6_ADDRSTRLEN);
			printf("resolved ip: %s\n", str);
		}
		else {
			answer.name =(unsigned char *)answer.resource + sizeof(rr_const_fields_t) + ntohs(answer.resource->data_len);
		}
	}
}
*/
void parse_dns_response(void *dns_packet) {

	query_t query;
    resource_record_t answer;
	char *current;
	int type;

    dnshdr_t *dns_header = (dnshdr_t *)dns_packet;
	int id = ntohs(dns_header->id);
    int num_questions = ntohs(dns_header->qdcount);
    int num_answers = ntohs(dns_header->ancount);
	
	// Point to the Query section
    current = (char *)dns_packet + sizeof(dnshdr_t);

	parse_query(dns_packet, current, &query);

	type = ntohs(query.question->qtype);
	if (type == TYPE_A || type == TYPE_AAAA) {
		
		printf("domain name: %s\n", query.qname);

		// point to the answer section
		current = current + query.qname_length +sizeof(question_const_fields_t);

		parse_answer(dns_packet, current, &answer);
		
		free(answer.name);
	}

	free(query.qname);
	return;
}
