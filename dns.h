#ifndef DNS_H
#define DNS_H

#define MAX_NAME_LEN 253
#define COMPRESSED_PTR 192 //0b11000000
#define TYPE_A 1
#define TYPE_AAAA 28

/* DNS header packed structure
 * Host byte order implementation
 * Bit fields are used
 */
typedef struct dnshdr {
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

	unsigned short qdcount; // number of question entries
	unsigned short ancount; // number of answer entries
	unsigned short nscount; // number of authority entries
	unsigned short arcount; // number of resource entries
} dnshdr_t;

//Constant sized fields of query structure
typedef struct question_const_fields {
	unsigned short qtype;
	unsigned short qclass;
} question_const_fields_t;

//Constant sized fields of the resource record structure
typedef struct rr_const_fields {
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
} rr_const_fields_t;

/* Structure of a resource record
 * The size is incorrect because the qname field does not have a constant size
 */
typedef struct resource_record {
	unsigned char *name;
	unsigned int name_length;
	rr_const_fields_t *resource;
	unsigned char *rdata;
} resource_record_t;

/* Structure of a Query section
 * The size is incorrect because the qname field does not have a constant size
 */
typedef struct query {
	unsigned char *qname;
	unsigned int qname_length;
	question_const_fields_t *question;
} query_t;

void parse_dns_response(void *buffer);

#endif //DNS_H