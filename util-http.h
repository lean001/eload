#ifndef _ELOAD_HTTP_H_
#include "eload.h"

#define HTTP_GET_TEMP "GET %s HTTP/1.0\r\nUser-Agent: eload/1.0\r\nAccept: */*\r\nHost: %s\r\nConnection: Close\r\n\r\n"
#define HTTP_POST_TEMP "POST %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: eload/1.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip,deflate\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nConnection: Close\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n"
#define HTTP_CONTENT_TEXT "text/plain"
#define PROTO_HTTP  0
#define PROTO_HTTPS 1
#define PROTO_ERROR 2


#define MTD_GET     0
#define MTD_POST    1
#define MTD_ERROR   2

int http_config_init();
void http_config_free();

char* http_get_host(uint8_t *url, uint32_t url_len, uint32_t *host_len);
char* http_get_uri(uint8_t *url, uint32_t url_len, uint32_t *uri_len);
int http_get_protocol(uint8_t *url, uint32_t url_len);
int http_get_method(uint8_t *url, uint32_t url_len);
int http_get_port(uint8_t * url, uint32_t url_len);

uint16_t http_status_parser(uint8_t *data, uint32_t data_len);

#endif
