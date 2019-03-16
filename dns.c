#include "dns.h"

void parse_dns_response(void *buffer) {

    //unsigned char *seek_ptr = buffer;
    dnshdr_t *dns_header = (dnshdr_t *)buffer;
    unsigned int num_questions = ntohs(dns_header->qdcount);
    unsigned int num_answers = ntohs(dns_header->ancount);
    
    query_t *query = buffer + sizeof(dnshdr_t);
    resource_record_t *answer;

    query->qname_length = strlen(query->qname_length) + 1;
    query->question = query->qname + query->qname_length;
    
    


	//move ahead of the dns header and the query field
// &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	printf("\nThe response contains : ");
	printf("\n %d Questions.",ntohs(dns->q_count));
	printf("\n %d Answers.",ntohs(dns->ans_count));
	

	//Start reading answers
	stop=0;

	for(i=0;i<ntohs(dns->ans_count);i++)
	{
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
		{
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(answers[i].resource->data_len);
		}
		else
		{
			answers[i].rdata = ReadName(reader,buf,&stop);
			reader = reader + stop;
		}
	}

	//read authorities
	for(i=0;i<ntohs(dns->auth_count);i++)
	{
		auth[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		auth[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		auth[i].rdata=ReadName(reader,buf,&stop);
		reader+=stop;
	}

	//read additional
	for(i=0;i<ntohs(dns->add_count);i++)
	{
		addit[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		if(ntohs(addit[i].resource->type)==1)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(j=0;j<ntohs(addit[i].resource->data_len);j++)
			addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		}
		else
		{
			addit[i].rdata=ReadName(reader,buf,&stop);
			reader+=stop;
		}
	}

	//print answers
	printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
	for(i=0 ; i < ntohs(dns->ans_count) ; i++)
	{
		printf("Name : %s ",answers[i].name);

		if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
		{
			long *p;
			p=(long*)answers[i].rdata;
			a.sin_addr.s_addr=(*p); //working without ntohl
			printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		
		if(ntohs(answers[i].resource->type)==5) 
		{
			//Canonical name for an alias
			printf("has alias name : %s",answers[i].rdata);
		}

		printf("\n");
	}

	//print authorities
	printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
	for( i=0 ; i < ntohs(dns->auth_count) ; i++)
	{
		
		printf("Name : %s ",auth[i].name);
		if(ntohs(auth[i].resource->type)==2)
		{
			printf("has nameserver : %s",auth[i].rdata);
		}
		printf("\n");
	}

	//print additional resource records
	printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
	for(i=0; i < ntohs(dns->add_count) ; i++)
	{
		printf("Name : %s ",addit[i].name);
		if(ntohs(addit[i].resource->type)==1)
		{
			long *p;
			p=(long*)addit[i].rdata;
			a.sin_addr.s_addr=(*p);
			printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		printf("\n");
	}
	return;
}

/*
 * 
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}

	name[p]='\0'; //string complete
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++) 
	{
		p=name[i];
		for(j=0;j<(int)p;j++) 
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0'; //remove the last dot
	return name;
}