#include "util-http.h"
#include <sys/types.h>
#include <regex.h>


static regex_t _url_reg;

int http_config_init()
{
#define HTTP_URL_MATCH_PATTERN "(https?)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]"
    int ret = regcomp(&_url_reg, HTTP_URL_MATCH_PATTERN, REG_EXTENDED|REG_NOSUB|REG_NEWLINE);
    if( ret != 0){
        char buf[1024];
        regerror(ret, &_url_reg, buf, sizeof(buf));
        fprintf(stderr, "%s: %s\n", __func__, buf);
        return -1;
    }
    return 0;
}

void http_config_free()
{
    regfree(&_url_reg);
}

#if 1
uint16_t http_status_parser(uint8_t *data, uint32_t data_len)
{
#define MIN_HTTP_STATUS_LINE 15

    uint8_t tmp[8];
    uint8_t *left, *right;
    
    if(data_len < MIN_HTTP_STATUS_LINE || strncasecmp("HTTP/", data, 5) != 0){
        /* 首行不是 HTTP */
        fprintf(stderr, "[Warn] unknown format: http respond line\n");
        return 0;
    }

    left = (data+5);
    while(*left !=' ' && *left != '\0') 
        left++;

    if(*left != ' ') return 0;

    left++;
    right = left;
    while(*right != ' ' && *right !='\0'){
        if(*right < '0' || *right > '9') break;
        right++;
    }
    if(*right != ' ') return 0;
    if(3 != right - left) return 0;

    int num = (*left - '0')*100 + (*(left+1) - '0')*10 + (*(left+2) - '0');
    if(num > 1000) return 0;
    return num; 
}

#else

int http_status_parser(uint8_t *data, uint32_t data_len, 
    uint16_t *status, uint32_t *content_length)
{
#define MIN_HTTP_STATUS_LINE 15
#define HTTP_CRLF "\r\n"

    uint32_t parsed = 0;
    uint32_t i = 0;

    if(*status == 0){/* 解析响应状态码 */
        *status = http_get_status();
    }

    if(*content_length == 0){ /* 解析Content_Length字段 */
        for (; i < data_len; ++i) {
            const char *p = HTTP_CRLF;
            while (*p) {
                if (data[i] == *p++)
                    goto next;
            }
            if(*content_length == 0 && strncasecmp(data[i], "Content-Length:", 15) == 0){
                
            }
            next:
            ++count;
        }     
    }
    return data_len - parsed;
}
#endif

int http_url_is_vaild(uint8_t *url, uint32_t url_len)
{
    assert(&_url_reg != NULL);

    regmatch_t pm[1];
    const size_t nmatch = 1;

    return regexec(&_url_reg, url, nmatch, pm, 0);
}


/*
* 先检测url合法性再用
*
*/
char* http_get_host(uint8_t *url, uint32_t url_len, uint32_t *host_len)
{
    int len = 0;
    char *host = NULL;
    uint8_t *left, *right;

    if(strncmp(url, "http://", 7) == 0)
        left = (url + 7);
    else if(strncmp(url, "https://", 8) == 0)
        left = (url + 8);
    
    if(left == NULL) left = url;

    right = strchr(left, ':');    /* xxx.xxx.com:123/ */
    if(right){
        goto found;
    }
    right = strchr(left, '/');    /* xxx.xxx.com/xxx */
    if(right){
        goto found;
    }
    right = (url + url_len);       /* xxx.xxx.com */

found:
    len = right - left;
    host  = malloc(sizeof(uint8_t) * (len + 1));
    if(!host) return NULL;
    
    *host_len = snprintf(host, len+1, "%.*s", len, left);
    return host;
}



char* http_get_uri(uint8_t *url, uint32_t url_len, uint32_t *uri_len)
{
#define HTTP_DEFAULT_URI "/"
#define HTTP_DEFAULT_URI_LEN 1

    char *uri = NULL;
    uint8_t *left, *right;

    if(strncmp(url, "http://", 7) == 0)
        left = (url + 7);
    else if(strncmp(url, "https://", 8) == 0)
        left = (url + 8);
    else{
        fprintf(stderr, "[Error] the url must be start with http(s): %s\n", url);
        return NULL;
    }

    right = strchr(left, '/');
    if(!right){
        uri = strdup(HTTP_DEFAULT_URI);
        *uri_len = HTTP_DEFAULT_URI_LEN;
        return uri;
    }

    uri = strdup(right);
    *uri_len = url_len - (right - url);
    return uri;
}

/*
http or https
*/
int http_get_protocol(uint8_t *url, uint32_t url_len)
{
    if(strncmp(url, "http://", 7) == 0){
        return PROTO_HTTP;
    }else if(strncmp(url, "https://", 8) == 0){
        return PROTO_HTTPS;
    }
    fprintf(stderr, "[Error] the url must be start with http(s): %s\n", url);
    return PROTO_ERROR;

}

int http_get_method(uint8_t *url, uint32_t url_len)
{
    //TODO
    return MTD_GET;
}

int http_get_port(uint8_t *url, uint32_t url_len)
{
#define HTTP_DEFAULT_PORT  80
#define HTTPS_DEFAULT_PORT  443

    char tmp[8];
    int port = 0;
    uint8_t *left, *right;
    if(strncmp(url, "http://", 7) == 0){
        left = (url + 7);
        port = HTTP_DEFAULT_PORT;
    }else if(strncmp(url, "https://", 8) == 0){
        left = (url + 8);
        port = HTTPS_DEFAULT_PORT;
    }else{
        fprintf(stderr, "[Error] the url must be start with http(s): %s\n", url);
        return port;
    }

    right = strchr(left, ':');   /* 使用默认端口 */
    if(!right) return port;

    right++;
    left = right;
    while(*right >= '0' && *right <= '9') right++;

    if(*right != '/' && right != '\0'){       /* www.xxx.xxx:888 */
        fprintf(stderr, "[Error] Invalid url for get port: %s\n", url);
        return 0;
    }
    snprintf(tmp, sizeof(tmp), "%.*s", right-left, left);
    port = atoi(tmp);
    
    if(port <= 0 || port > 65535){
        fprintf(stderr, "[Error] Invalid url for get port: %s\n", url);
        return 0;
    }
    return port;
}


