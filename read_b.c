/*
 * @author: Gowrima Jayaramu
 * July 13 2021
 *
 * DNS message parser
 * Parse DNS header and payload from a stream of hex bytes
 * 
 * Input: stream of bytes in hex
 * Output: DNS header, question and answer
 *
 * Expected input: 
 * "\x6d\x7c \x81\x80 \x00\x01 \x00\x01 \x00\x00 \x00\x00 \x07\x65 \x78\x61" \
"\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00" \
"\x01\x00\x01\x00\x01\x2a\x67\x00\x04\ x5d\xb8\xd8\x22"

	Expected ouput:
	./a.out
"\x6d\x7c \x81\x80 \x00\x01 \x00\x01 \x00\x00 \x00\x00 \x07\x65 \x78\x61" \
"\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00" \
"\x01\x00\x01\x00\x01\x2a\x67\x00\x04\ x5d\xb8\xd8\x22"

;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 28028
;; Flags: qr rd ra; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 0

;; QUESTION SECTION:
;; example.com.                 IN      A

;; ANSWER SECTION:
example.com.            76391   IN      A       93.184.216.34
gowrima@Gowrimas-MacBook-Pro interview_code % 
	
 *
 * */


#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>

#define DOMAIN_NAME_END "00"

#define OPCODE_STR(opcode, opcode_str)\
{\
    switch(opcode) {\
    case 0:\
        opcode_str = "QUERY";\
        break;\
    case 1:\
        opcode_str = "IQUERY";\
        break;\
    case 2:\
        opcode_str = "STATUS";\
        break;\
    default:\
        opcode_str = "UNKNOWN";\
        break;\
    }\
}

#define RESPONSE_STR(type_code, type_str)\
{\
  switch(type_code) {\
  case 0:\
    type_str = "NOERROR";\
    break;\
  case 1:\
    type_str = "FORMAT ERROR";\
    break;\
  case 2:\
    type_str = "SERVER FAILURE";\
    break;\
  case 3:\
    type_str = "NAME ERROR";\
    break;\
  case 4:\
    type_str = "NOT IMPLEMENTED";\
    break;\
  case 5:\
    type_str = "REFUSED";\
    break;\
  default:\
    type_str = "UNKNOWN";\
    break;\
  }\
}

#define QTYPE_STR(type, str)\
{\
    switch(type) {\
    case 1:\
        str = "A";\
        break;\
    case 2:\
        str = "NS";\
        break;\
    default:\
        str="UNKOWN";\
        break;\
    }\
}  

typedef struct dns_header {
    unsigned short id;
    unsigned qr:1;
    unsigned opcode:4;
    unsigned aa:1;
    unsigned tc:1;
    unsigned rd:1;
    unsigned ra:1;
    unsigned rcode:4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
    
} dns_header;
dns_header *new_header;

typedef struct dns_question {
  char qname[255];
  unsigned short qtype;
  unsigned short qclass;
    
} dns_question;
dns_question *dns_q;

typedef struct domain_name_label {
    int label_index;
    int label_count;
} domain_name_label;

typedef struct dns_answer {
    char name[255];
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
    char rdata[128];
} dns_answer;
dns_answer *dns_a;

void parse_dns_message(char* message[], int message_len);
void parse_dns_header(char* tokens[]);
void parse_dns_question(char* tokens[]);
void parse_dns_answer(char* tokens[]);
int next_token_id = 0;

void parse_dns_message(char* message[], int message_len) {
    if (message == NULL || *message == 0) {
        printf("DNS message is NULL\n");
        return;
    }
  
    char* tokens[512];
    int n = 0;
 
    for (int i = 0; i < message_len; i++) {
        // parse the bytes
        char* line = message[i];
        //printf("line = %s\n", line);
        
        char* token = strtok(line, "\\x");
        while (token != NULL) {

            if (n >= 512) {
                break;
            }
            if (strlen(token) > 2) {
                *(token+2) = '\0';
            }
            if (strlen(token) == 2) {
                tokens[n++] = token;
            }

            token = strtok(NULL, "\\x"); 
        }
    }

    //for (int i = 0; i !=n; i++) {
    //        printf("token[%d] = %s\n", i, tokens[i]);
    //    }
    parse_dns_header(tokens);
    parse_dns_question(tokens);
    parse_dns_answer(tokens);

    return;
}

void parse_dns_header(char* tokens[]) {
    
    new_header = (dns_header*) (malloc(sizeof(dns_header)));
    if (new_header == NULL) {
        printf("Memory alloc failure for dns header\n");
        exit(0);
    }    
       // copy the bytes to datastructures
    char str[16];
    
    strncpy(str, tokens[next_token_id++], 16);
    strncat(str, tokens[next_token_id++], 16);
    short id = (short) strtol(str, NULL, 16);
    new_header->id = id;
    
    strcpy(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    long flags = strtol(str, NULL, 16);
    
    new_header->qr = (flags >> 15) & 0x01;
    new_header->opcode = flags & (0xF << 11);
    new_header->aa = (flags >> 10) & 0x01;
    new_header->tc = (flags >> 9) & 0x01;
    new_header->rd = (flags >> 8) & 0x01;
    new_header->ra = (flags >> 7) & 0x01;
    new_header->rcode = flags & 0xF;
    
    strcpy(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    long qdcount = strtol(str, NULL, 16);
    new_header->qdcount = qdcount;

    strcpy(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    long ancount = strtol(str, NULL, 16);
    new_header->ancount = ancount;

    strcpy(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    long nscount = strtol(str, NULL, 16);
    new_header->nscount = nscount;

    strcpy(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    long arcount = strtol(str, NULL, 16);
    new_header->arcount = arcount;

    //printf("qr = %d\topcode = %d\taa = %ld\ttc=%d\trd = %d\tra = %d\trcode=%d\n", new_header->qr,
    //    new_header->opcode, new_header->aa, new_header->tc, new_header->rd, new_header->ra, new_header->rcode);
    return;
}
    
void parse_dns_question(char* tokens[]) {

    dns_q = (dns_question*) malloc(sizeof(dns_question));
    if (dns_q == NULL) {
        printf("Memory alloc failure for dns question\n");
        exit(1);
    }
    
    char str[16];
    int domain_name_len = 0, lable_count = 0, j = 0;

    // label begins at lable+1 and ends at lable+lable_count
    // next label is at lable+lable_count+1
    int cur_label = 12;
    domain_name_label labels[10] = {0};
    domain_name_label dn;
    int la_id = 0;

    while (strcmp(tokens[cur_label], DOMAIN_NAME_END) !=0) {
            
        lable_count = (int) strtol(tokens[cur_label], NULL, 16); // first label

        dn.label_index = cur_label;
        dn.label_count = lable_count;
        
        cur_label = cur_label+lable_count+1;

        labels[la_id++] = dn;
        //printf("lable_count = %d cur_label = %d\n", lable_count, cur_label);
        domain_name_len += lable_count;
    }

    //printf("domain name len = %d\n", domain_name_len);

    char* domain_name = (char*) malloc(sizeof(char)*domain_name_len);
    int i = 0, k = 1, label_index = 0;

    while (i <= la_id) {
        //fetch domain name of lable_count bytes long
        label_index = labels[i].label_index;
        lable_count = labels[i].label_count;
        i++;
        
        while (k <= lable_count) {
            int ascii = (int) strtol(tokens[label_index + k], NULL, 16);
            //printf("ascii = %c j = %d\n", ascii, j);
            domain_name[j++] = ascii;
            //printf("domain_name = %s\n", domain_name);
            k++;
        }
        if (i <= la_id) {
            domain_name[j++] = '.';
        }
        k = 1;
        //printf("i = %d la_id = %d\n", i, la_id);
    }

    //printf("domain_name = %s\n", domain_name);
    strncpy(dns_q->qname, domain_name, domain_name_len+2);
    //printf("dns->qname = %s\n", dns_q->qname);

    dn = labels[la_id-1];
    next_token_id = dn.label_index+dn.label_count+2;;

    strcpy(str, tokens[next_token_id++]);
    strncat(str, tokens[next_token_id++], 2);
    long type = strtol(str, NULL, 16);
    dns_q->qtype = type;
    
    strcpy(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    int class = (int) strtol(str, NULL, 16);
    dns_q->qclass = class;

    return;    
}

void parse_dns_answer(char* tokens[]) {

    dns_a = (dns_answer*) malloc(sizeof(dns_answer));
    if (dns_a == NULL) {
        printf("No memory allocated for dns answer\n");
        exit(1);
    }

    char str[32];

    strcpy(dns_a->name, dns_q->qname);

    next_token_id += 2;

    strcpy(str, tokens[next_token_id++]);
    strncat(str, tokens[next_token_id++], 2);
    long type = strtol(str, NULL, 16);
    dns_a->type = type;

    strcpy(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    int class = (int) strtol(str, NULL, 16);
    dns_a->class = class;
    
    strcpy(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    strcat(str, tokens[next_token_id++]);
    long ttl = strtol(str, NULL, 16);
    dns_a->ttl = ttl;

    strcpy(str, tokens[next_token_id++]);
    strncat(str, tokens[next_token_id++], 16);
    long rd_len = strtol(str, NULL, 16);
    dns_a->rdlength = rd_len;
    
    int ip;

    if (rd_len == 4) {
        strcpy(str, tokens[next_token_id++]);
        strcat(str, tokens[next_token_id++]);
        strcat(str, tokens[next_token_id++]);
        strcat(str, tokens[next_token_id++]);
        ip = (int) strtol(str, NULL, 16);
    }

    snprintf(dns_a->rdata, 40, "%d.%d.%d.%d", 
            (ip >> 24 & 0xFF), 
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            (ip & 0xFF));

    //printf("IP = %s\n", dns_a->rdata);

    return;
    
}

void print_dns_message() {

    if (new_header == NULL) {
        printf("header is null\n");
        return;
    }

    char* opcode_str, *rcode_str;
    OPCODE_STR(new_header->opcode, opcode_str);
    RESPONSE_STR(new_header->rcode, rcode_str);

    printf(";; ->>HEADER<<- opcode: %s; status: %s; id: %d\n", opcode_str, 
        rcode_str, new_header->id);
    
    printf(";; Flags: %s %s %s; QUERY: %d; ANSWER: %d; AUTHORITY: %d; ADDITIONAL: %d\n", 
        new_header->qr?"qr":" ", new_header->rd ? "rd":" ", new_header->ra?"ra":" ", 
            new_header->qdcount, new_header->ancount, new_header->nscount, new_header->arcount);

    char* qtype_str;
    QTYPE_STR(dns_q->qtype, qtype_str);
    printf("\n;; QUESTION SECTION:\n");
    printf(";; %s\t\t\t%s\t%s\n", dns_q->qname, "IN", dns_q->qtype?qtype_str:"N/A");
   
    printf("\n;; ANSWER SECTION:\n");
    printf("%s\t\t%d\t%s\t%s\t%s\n", dns_a->name, dns_a->ttl, "IN", dns_a->type?qtype_str:"N/A",
            dns_a->rdata);

    return;
}

int main() {
    /* Enter your code here. Read input from STDIN. Print output to STDOUT */ 
    char str[100];
    char* buffer[32];
    int i = 0;
    
    while (fgets(str, 100, stdin) != NULL) {
        if (*str == '\n') {
            break;
        }
        
        buffer[i] = strndup(str, 100);
        i++;
    }
    
    parse_dns_message(buffer, i);
    print_dns_message();
    
    for (int j = 0; j < i; j++) {
        free(buffer[j]);
    }
    
    free(new_header);
    free(dns_q);    
    free(dns_a);

    return 0;
}
