

# About

m_dnscore is DNS query packet builder, response parser, no dependence. 

only support ipv4 with standard query, and fetch 1st result from response.


# Usage

```c
// 1. construct DNS query, send to UDP:53
uint8_t req_buf[1024];
memset(req_buf, 0, 1024);

int qid = random();
int query_size = mdns_query_build(req_buf, qid, "google.com")
if (query_size > 0) {
    send(req_buf, query_size);
}
// store (domain, qid, query_size) for later check

// ...

// 2. get DNS response qid
uint8_t out_ipv4[4];
int qid = mdns_response_fetch_qid(rep_buf, content_length);

// 3. check domain, query_size, get out_ipv4
if (qid > 0 &&
    mdns_response_parse(rep_buf, content_length, query_size, domain, out_ipv4) > 0)
{
    char ipv4[16];
    memset(ipv4, 0, 16);
    snprintf(ipv4, 16, "%d.%d.%d.%d", out_ipv4[0], out_ipv4[1], out_ipv4[2], out_ipv4[3]);
    printf("get ipv4 %s\n", ipv4);
}
```
