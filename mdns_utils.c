/* 
 * Copyright (c) 2020 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mdns_utils.h"

/* structures for DNS query
 */

typedef struct {
   unsigned short id;            // identification number

   /** flags in a diferent order than in DNS RFC, because of the
       network byte order (big-endian) ; locally it's
       little-endian ; and that contains bitfields, they are
       put from the least significant bit of the least
       significant byte.
   */
   unsigned short
      rd: 1,                    // recursion desired
      tc: 1,                    // truncated message
      aa: 1,                    // authoritive answer
      opcode: 4,                // purpose of message 
      qr: 1,                    // query/response flag
      rcode: 4,                 // response code
      z: 3,
      ra: 1;                    // recursion available
    
   unsigned short qdcount;
   unsigned short ancount;
   unsigned short nscount;
   unsigned short arcount;
} dns_header_t;

typedef struct {
   unsigned short qtype;
   unsigned short qclass;
} dns_question_t;

typedef struct {
   unsigned short type; //two octets containing one of the RR TYPE codes
   unsigned short _class;
   unsigned int ttl;
   unsigned int rdlen:16;      // length of rdata
   unsigned int none:16;       // for pading, need to remove when sizeof
} dns_rr_data_t;

/* the real size for rr data */
static inline int
_sizeof_dns_rr_data(void) {
   return sizeof(dns_rr_data_t) - 2;
}

/* 
 */

#define DNS_SVR_PORT 53
#define DNS_BUF_SIZE 1024
#define QUERY_DOMAIN_LEN  256

/* validate label length */
static inline int
_get_label_len(uint8_t *buf, int pos, int llen) {
   if (llen>63 || llen<=0) {
      return 0;
   }
   buf[pos] = llen;
   return 1;
}

static int
_construct_domain_field(uint8_t *buf, const char *domain) {
   buf[0] = '.';
   int i=0, j=0, dot=0;
   for (; domain[i] && i<QUERY_DOMAIN_LEN; i++) {
      if (domain[i] == '.') {
         if ( !_get_label_len(buf, j, i - j) ) {
            return 0;
         }
         j = 1 + i;
         dot += 1;
      } else {
         buf[1 + i] = domain[i];
      }
   }

   if ( !_get_label_len(buf, j, i - j) ) {
      return 0;
   }

   if (dot<1 || i>255) {
      return 0;
   }

   return i + 1;
}

static int
_response_check_header(const uint8_t *buf) {
   const dns_header_t *rh = (dns_header_t*)buf;
   const int code = rh->rcode;
   
   if (//(rh->id != qid) || // check qid in fetch id phrase
       (rh->qr != 1) ||
       (rh->opcode != 0) ||
       (rh->rd != 1) ||
       (rh->z != 0) ||
       (rh->qdcount != htons(1)) ||
       (rh->ancount == 0 && code == 0) ||
       (code >= 6 && code <= 15))
   {
      return 0;
   }

   if (code>=1 && code<=5) {
      return 0;
   }

   return 1;   
}

static int
_response_check_question(const uint8_t *buf,
                         int query_size,
                         const char *domain)
{
   char *rqname = (char *)&buf[sizeof(dns_header_t)];
   dns_question_t *rq = (dns_question_t *)&buf[query_size - sizeof(dns_question_t)];

   int len = strlen(domain);
   uint8_t domain_buf[QUERY_DOMAIN_LEN];
   _construct_domain_field(domain_buf, domain);

   if (strncmp(rqname, (char *)domain_buf, len)) {
      return 0;
   }

   if (!(rq->qtype==0 && rq->qclass==htons(1))) {
      // ignore qtype and qclass
      //return 0;
   }
   
   return 1;
}

/* fetch rr_data from response, output ipv4 */
static int
_response_fetch_res(const uint8_t *buf,
                    int content_len,
                    int query_size,
                    uint8_t *out_ipv4)
{
   const dns_header_t *rh = (dns_header_t*)buf;
   int aname_size = 0;   
   char *rsp_aname = NULL;
   dns_rr_data_t *rsp_answer = NULL;

   int prev_size = query_size;
   
   for (int i=0; i<ntohs(rh->ancount); i++) {
      //printf("prev_size: %d\n", prev_size);
       
      if (content_len <= (prev_size + 2 + (int)sizeof(dns_header_t))) {
         return 0;
      }

      rsp_aname = (char*)&buf[prev_size];
      //printf("rsp name %d\n", (int)strlen(rsp_aname));      

      if ((aname_size = strlen(rsp_aname)) < 2 ||
          content_len <= (prev_size + aname_size + _sizeof_dns_rr_data()))
      {
         //printf("aname_size %d\n", aname_size);
         return 0;
      }

      rsp_answer = (dns_rr_data_t*)&buf[prev_size + aname_size];

      if (content_len < (prev_size +
                         aname_size +
                         _sizeof_dns_rr_data() +
                         ntohs(rsp_answer->rdlen)))
      {
         //printf("incomplete DNS response 2\n");
         return 0;
      }

      const unsigned short v1 = ntohs(1);
      if (rsp_answer->_class == v1 &&
          (rsp_answer->type == v1 || rsp_answer->type==ntohs(12)))
      {
         int offset = prev_size + aname_size + _sizeof_dns_rr_data();
         uint8_t *result = (uint8_t*)&buf[offset];
         memcpy(out_ipv4, result, 4);
         return 1;
      }

      prev_size = prev_size + aname_size + _sizeof_dns_rr_data() + ntohs(rsp_answer->rdlen);
   }

   //printf("unable to find IP record\n");
   return 0;
}

/* Public Interface
 */

int
mdns_query_build(uint8_t *buf,
                 unsigned short qid,
                 const char *domain)
{
   if (!buf || qid==0 || !domain) {
      return 0;
   }

   uint8_t domain_buf[QUERY_DOMAIN_LEN];
   memset(domain_buf, 0, QUERY_DOMAIN_LEN);
   
   uint8_t dlen = _construct_domain_field(domain_buf, domain);
   if (dlen == 0) {
      return 0;
   }

   int query_size = sizeof(dns_header_t) + dlen + 1 + sizeof(dns_question_t);
   memset(buf, 0, DNS_BUF_SIZE);

   dns_header_t *h =  (dns_header_t*)buf;
   h->id = qid;
   h->qr = 0;                   /* this is a query */
   h->opcode = 0;               /* this is a standard query */
   h->aa = 0;                   /* NOT Authoritative */
   h->tc = 0;                   /* not truncated */
   h->rd = 1;                   /* Recursion Desired */
   h->ra = 0;                   /* Recursion not available */
   h->z = 0;
   h->rcode = 0;
   
   h->qdcount = htons(1);
   h->ancount  = 0;
   h->nscount = 0;
   h->arcount  = 0;
   
   /* fill qname */
   char *qname = (char*)&buf[sizeof(dns_header_t)];
   memcpy(qname, domain_buf, dlen);
   
   dns_question_t *q = (dns_question_t*)&buf[sizeof(dns_header_t) + dlen + 1];
   q->qtype = htons(1);         /* IPv4 */
   q->qclass = htons(1);        /* internet */

   return query_size;
}

int
mdns_response_fetch_qid(const uint8_t *buf, int content_len) {
   if (!buf) {
      return 0;
   }
   const dns_header_t *rh = (dns_header_t*)buf;
   return rh->id;   
}

int
mdns_response_parse(uint8_t *buf,
                    int content_len,
                    int query_size,
                    const char *domain,
                    uint8_t *out_ipv4)
{
   if (!buf || content_len<=0 || query_size<=0 || !domain || !out_ipv4) {
      return 0;
   }
   
   if (_response_check_header(buf) &&
       _response_check_question(buf, query_size, domain) &&
       _response_fetch_res(buf, content_len, query_size, out_ipv4))
   {
      return 1;
   }

   return 0;
}
