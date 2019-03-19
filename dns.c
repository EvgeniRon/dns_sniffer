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
			seek_ptr = &dns_packet[((slen & 0x3f)<<8) + *seek_ptr];	// Follow compressed pointer
			if(!jumped) {
				clen++;
			}	
			jumped = 1;			
			slen = *seek_ptr++;
			if (slen > MAX_SEGMENT_LENGTH) {
				fprintf(stderr, "Segment length error!\n");
				return EXIT_FAILURE;
			}
		}

		if (slen == 0) {
			break;	// zero length == all done
		}			

		if (!jumped) {
			clen += slen;
		} 

		if((name_max_length -= slen+1) < 0)
		{
			fprintf(stderr,"Not enough memory");
			return 0;
		}
		
		while (slen-- > 0) {
			*name++ = *seek_ptr++;
		}

		*name++ = '.';

		nseg++;
	}

	if(nseg == 0) {
		*name++ = '.';	// Root name; represent as single dot
	}	
	else {
		--name;
	} 

	*name = '\0';

	return clen; // Length of compressed message
}

static int parse_query(char *dns_packet, char *seek_ptr, query_t *query) {
	char qname[MAX_NAME_LEN];

	query->qname_length = parse_name(dns_packet,seek_ptr, &qname[0], sizeof(qname));
	if (query->qname_length == 0) {
		fprintf(stderr, "Failed reading field name.\n");
		return EXIT_FAILURE;
	}

	query->qname = malloc(sizeof(char) * query->qname_length);
	memcpy(query->qname, &qname, query->qname_length);

	// Point to the QTYPE and QCLASS fields
    query->question = (question_const_fields_t *)(seek_ptr + query->qname_length);
	
	return EXIT_SUCCESS;
}

static int parse_answer(char *dns_packet, char *seek_ptr, resource_record_t *answer) {
	char name[MAX_NAME_LEN];
	int uncompressed_name_length;
                                                                                                                                                                                                                
	// Get the name and its length - the length may be smaller than the string itself (compressed pointer)
	answer->name_length = parse_name(dns_packet, seek_ptr, &name[0], sizeof(name));
	if (answer->name_length == 0) {
		fprintf(stderr, "Failed reading field name.\n");
		return EXIT_FAILURE;
	}

	uncompressed_name_length = strlen(name);
	
	answer->name = malloc(sizeof(char) * (uncompressed_name_length + 1));
	memcpy(answer->name, &name, uncompressed_name_length);
	answer->name[uncompressed_name_length] = '\0';

	seek_ptr += answer->name_length; // Skip name field
	answer->resource = (rr_const_fields_t *)seek_ptr;

	seek_ptr += 2; // Skip Type field (2 bytes size)
	seek_ptr += 2; // Skip Class field (2 bytes size)
	seek_ptr += 4; // Skip TTL field (4 bytes)
	seek_ptr += 2; // Skip RDLENGTH field (2 bytes)
	answer->rdata = seek_ptr;
	
	return EXIT_SUCCESS;
}

void parse_dns_response(void *dns_packet) {
	char ip_str[INET6_ADDRSTRLEN];
	query_t query;
    resource_record_t answer;
	char *current;
	int type;
	int ret;

    dnshdr_t *dns_header = (dnshdr_t *)dns_packet;
	int id = ntohs(dns_header->id);
    int num_questions = ntohs(dns_header->qdcount);
    int num_answers = ntohs(dns_header->ancount);

	// Point to the Query section
    current = (char *)dns_packet + sizeof(dnshdr_t);

	ret = parse_query(dns_packet, current, &query);
	if(ret == EXIT_FAILURE) {
		return;
	}

	// Continue working on IP queries only
	type = ntohs(query.question->qtype);
	if (type == TYPE_A || type == TYPE_AAAA) {

		// point to the answer section
		current = current + query.qname_length +sizeof(question_const_fields_t);
		
		// loop through all the answers
		for (int i = 0; i < num_answers - 1; i++) {
			ret = parse_answer(dns_packet, current, &answer);
			if(ret == EXIT_FAILURE) {
				return;
			}
			
			// print only answers with IP
			type = ntohs(answer.resource->type);
			if (type == TYPE_A || type == TYPE_AAAA) {
				printf("DNS Id: 0x%x:\nQuery domain name: %s\n", id, query.qname);
				switch(type) {
				case TYPE_A:
					printf("Answer name: %s IPv4: %s\n",answer.name, inet_ntop(AF_INET, answer.rdata, ip_str, INET_ADDRSTRLEN));
					break;
				case TYPE_AAAA:
					printf("Answer name: %s IPv6: %s\n", answer.name, inet_ntop(AF_INET6, answer.rdata, ip_str, INET6_ADDRSTRLEN));
					break;
				}
			}

			if (answer.name_length != 0) {
				free(answer.name);
				answer.name = NULL;
			}

			// Skip to next answer
			current += answer.name_length + ntohs(answer.resource->data_len) + RR_CONST_FIELDS_SIZE;
			answer.name_length = 0;
		}
	}

	free(query.qname);
	query.qname_length = 0;
	return;
}
