#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "dns.h"

/*
 * Parse the name field in DNS Resource Record
 * 
*/
static unsigned char *parse_query_name(unsigned char *name_field, int size) {

	unsigned char *name = (unsigned char *)malloc(sizeof(char) * size);
	unsigned char count = 0;
	int i = 0;

	if(size == 0) {
		return NULL;
	}

	if(*name_field >= COMPRESSED_PTR) {
		//TODO: Implement compressed name format
		fprintf(stderr, "Compressed name - unsupported\n");
		return NULL;
	}

	count = *name_field;
	name_field++;

	//read the names in 3www6google3com format
	while(i<size) {

		if (count == 0) {
			count = *name_field;
			if (count == 0) { // Reached end of line
				name[i] = '\0';
			}
			else {
				name[i] = '.';
			}
		}
		else {
			count--;
			name[i] = *name_field;
		}
		name_field++;
		i++;
	}
	return name;
}

static void parse_answer(unsigned char* name, int num_answers) {
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

void parse_dns_response(void *buffer) {

	query_t query;
    resource_record_t answer;
	unsigned char *domain_name;
	int type;

    dnshdr_t *dns_header = (dnshdr_t *)buffer;
    unsigned int num_questions = ntohs(dns_header->qdcount);
    unsigned int num_answers = ntohs(dns_header->ancount);
	printf("DNS ID: %x\n", ntohs(dns_header->id));
	// Point to the QNAME field in the Query section
    query.qname = (unsigned char *)buffer + sizeof(dnshdr_t);

	// The QNAME field length
	query.qname_length = strlen((const char*)query.qname) + 1;

	// Point to the QTYPE and QCLASS fields
    query.question = (question_const_fields_t *)(query.qname + query.qname_length);

	// We are interested only in type A (ipv4) and type AAAA (ipv6)
	type = ntohs(query.question->qtype);
	if (type == TYPE_A || type == TYPE_AAAA) {
		
		// Get the domain name from the query
		domain_name = parse_query_name(query.qname, query.qname_length);
		printf("domain name: %s\n", domain_name);

		answer.name = (unsigned char *)query.question + sizeof(question_const_fields_t);
		parse_answer(answer.name, num_answers);
		printf("-- END OF RECORD --\n\n");
		
		free(domain_name);
	}
	return;
}
