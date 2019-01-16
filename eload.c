/*
* 2019-1-08 09:06:04
* author: lean
* leannong@gmail.com
*/
#include "eload.h"
#include "util-http.h"
#include "util-epoll.h"
#include <netinet/in.h>
#include <sys/socket.h> 
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/resource.h>
#include <time.h>
#include <float.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>


#define MAX_BUF_LEN 2048
#define ELOAD_USEC_PER_SEC 1000000

enum procstat{
    PROC_ERROR = -1,
    PROC_NODO = 0,
    PROC_CLOSED
};


enum tcpstat{
    TCP_STAT_FREE = 0,
    TCP_STAT_CONN,
    TCP_STAT_WRITE,
    TCP_STAT_READ,
    TCP_STAT_CLOSED,
    TCP_STAT_TIMMEOUT,
    TCP_STAT_ERROR,
    TCP_STAT_MAX
};

typedef struct _tcpstat{
    int code;
    char *str;
}__tcpstat;

static __tcpstat tcpstat_to_string[]= {
    {TCP_STAT_FREE,     "unuse"},
    {TCP_STAT_CONN,     "connecting"},
    {TCP_STAT_WRITE,    "writing"},
    {TCP_STAT_READ,     "reading"},
    {TCP_STAT_CLOSED,   "closed"},
    {TCP_STAT_TIMMEOUT, "timeout"},
    {TCP_STAT_ERROR,    "error"},
    {TCP_STAT_MAX, NULL}
};

enum eloadstat{
    ELOAD_WAITING = 0,
    ELOAD_RUNING,
    ELOAD_DONE
};

#define HTTP_STATUS_NONE 0
#define HTTP_STATUS_DONE 1


typedef struct eload_conn_{

    struct timeval conn_at;
    struct timeval req_at;
    struct timeval res_at;
    struct timeval close_at; 

    int fd;
    uint32_t http_content_length;
    uint32_t http_content_recv;
    uint32_t server_index;
    uint16_t http_status;
    uint8_t  tcp_status;

    struct eload_conn_ *prev;
    struct eload_conn_ *next;
}eload_conn;

/*
用于连接超时管理
*/
typedef struct conn_mgt_{
    eload_conn *head;
    eload_conn *tail;
}conn_mgt;



typedef struct eload_thv_{
    struct timeval start_at;
    struct timeval end_at;
    pthread_t tid;
    uint32_t max_connections;          /* 线程最大连接数 */
    uint32_t per_connections;          /* 线程最大并发数 */
    uint32_t conn_err;
    uint32_t conn_done;
    uint32_t conn_active;
    uint32_t conn_timeout;
	uint32_t conn_free;
    uint8_t  done;
    eload_conn *conn_slot;             /* 工作线程连接槽 */
}eload_thv;

typedef struct __eload_addr_{
    uint8_t ip_str[INET6_ADDRSTRLEN];
    //struct sockaddr_in addr;
    socklen_t addr_len;
    int sock_family;
    int sock_type;
    int sock_protocol;
    uint8_t mask;               /* 用于标记能否连接 */
    struct __eload_addr_ *next;  
}eload_addr;

typedef struct eload_addr__{
    uint32_t payload_len;
    uint32_t host_len;
    uint32_t url_len;
    uint32_t uri_len;
    uint16_t port;
    uint8_t mask;               /* 用于标记能否连接 */
    uint8_t method;             /* GET OR POST */
    uint8_t protocol;           /* HTTP OR HTTPS */
    
    uint8_t *url;
    uint8_t *hostname;
    uint8_t *uri;
    uint8_t *payload;
    
    eload_addr *eaddr;    
}eload_addr_t;

typedef struct eload_ctx_{
    //eload_addr_t *addr_ctx;
    eload_thv *thrdata;              /*工作线程组数据*/
}eload_ctx;

static eload_conn *connections = NULL;
static uint8_t max_thread = 1;              /* 线程数 */
static int max_connections = 100;          /* 总连接数 */
static int per_connections = 10;           /* 并发数 */
static int http_status_buckets[1000];       /* http响应状态统计 */

static eload_addr_t *http_servers;
static uint32_t max_http_servers = 1;       /* 总的url数量 */
static uint8_t eload_state = ELOAD_WAITING;

static int eload_url_parser(char *urls, char *paths, char *code, uint32_t count);
static void eload_handle_disconn(eload_conn *conn_ctx, int status);
static void eload_conn_delete(conn_mgt *list, eload_conn *node, int status);
static void eload_conn_timeout_update(conn_mgt *list, eload_conn *node);
static int eload_handle_read(eload_conn *conn_ctx);
static int eload_handle_write(eload_conn *conn_ctx);
static void* eload_woker(void *arg);


static void eload_usage()
{
    fprintf(stderr, 
"\n\nUsage:\n eload [OPTIONS] http://hostname[:port]/path\n"
"    -h                show Usage\n"
"    -l <url>          example: -l 'http://www.qq.com/'\n"
"    -p <file>         the POST payload\n"
"    -T <content-type> Content-type header to use for POST data\n"
"                      eg. 'application/x-www-form-urlencoded'\n"
"    -c <connections>  total connections\n"
"    -t <thread>       the number of threads\n"
"    -r <rate>         N con/sec, NOTE: rate >= threads\n\n"
"     ./eload -t 1 -c 100 -r 10 -l 'http://www.qq.com/'\n"
"\n");
}


static int  eload_options_parser(eload_ctx *ctx, int argc, char **argv)
{
    int ch;
    int t_thr = max_thread;
    int c_conn = max_connections;
    int r_rate = per_connections;
    char *url = NULL;
    char *payload_path = NULL;
    char *payload_encode_type = NULL;
    while ((ch = getopt(argc, argv, "c:t:r:l:hT:p:")) != -1) {
        switch(ch){
            case 'h':
                return -1;
            case 'r':
                r_rate = atoi(optarg);
                break;
            case 'c':
                c_conn = atoi(optarg);
                break;
            case 't':
                t_thr = atoi(optarg);
                break;
            case 'l':
                if(url) free(url);
                url = strdup(optarg);
                break;
            case 'p':
                if(payload_path) free(payload_path);
                payload_path = strdup(optarg);
                break;
            case 'T':
                if(payload_encode_type) free(payload_encode_type);
                payload_encode_type = strdup(optarg);
                break;
            default:
                break;
        }
    }
    if(r_rate < t_thr){
        fprintf(stderr, "NOTE: must be rate >= threads\n");
        return -1;
    }
    max_thread = t_thr;
    max_connections = c_conn;
    per_connections = r_rate;

    if(eload_url_parser(url, payload_path, payload_encode_type, 1) != 0)  //TODO url 列表
        return -1;    

    free(url);
    if(payload_path) free(payload_path);
    if(payload_encode_type) free(payload_encode_type);
    
    return 0;
}


static int eload_rlimit_config()
{
    struct rlimit limits;
    
#ifdef RLIMIT_NOFILE
    /* Try and increase the limit on # of files to the maximum. */
    if (getrlimit(RLIMIT_NOFILE, &limits) == 0){
        if (limits.rlim_cur != limits.rlim_max){
            
            if (limits.rlim_max == RLIM_INFINITY)
                limits.rlim_cur = 8192;     /* arbitrary */

            else if (limits.rlim_max > limits.rlim_cur)
                limits.rlim_cur = limits.rlim_max;
            
            (void) setrlimit(RLIMIT_NOFILE, &limits);
        }
        if((size_t)per_connections > limits.rlim_cur){
            fprintf(stderr, "Too many open files, please increase ulimit before run eload\n");
            return -1;
        }
        return 0;

    }
    return -1;
#endif  
}

static eload_addr *eload_address_new(struct addrinfo *rp)
{
    eload_addr *s = malloc(sizeof(eload_addr));
    if(!s){
        fprintf(stderr, "[Error] %s: out of mem\n", __func__);
        return NULL;
    }
    memset(s, 0, sizeof(eload_addr));

    s->sock_family = rp->ai_family;
    s->sock_protocol = rp->ai_protocol;
    s->sock_type = rp->ai_socktype;
    s->next = NULL;
    s->mask = 0;
    //s->addr_len = addr_len;
    //memcpy(&s->addr, addr, addr_len);

    if(s->sock_family == AF_INET){
        struct sockaddr_in *in = (struct sockaddr_in *)rp->ai_addr;
        inet_ntop(rp->ai_family, &in->sin_addr, s->ip_str, sizeof(s->ip_str));
    }else{
        struct sockaddr_in6 *in = (struct sockaddr_in6 *)rp->ai_addr;
        inet_ntop(rp->ai_family, &in->sin6_addr, s->ip_str, sizeof(s->ip_str));
    }
    
    
    fprintf(stderr, "[DEBUG] %s: %s\n", __func__, s->ip_str);
    
    return s;
}

static void eload_address_free(eload_addr *list)
{
    eload_addr *tmp = NULL;
    
    while(list){
        tmp = list;
        list = list->next;
        free(tmp);
    }
}

static int eload_address_lookup(eload_addr_t *addr_ctx)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    eload_addr *addr_list = NULL, *addr_tmp;
    int s;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; //AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    
    if((s = getaddrinfo(addr_ctx->hostname, NULL, &hints, &result)) != 0){
        fprintf(stderr, "[Error] getaddrinfo failed: %s\n", gai_strerror(s));
        return -1;
    }
    for(rp = result; rp != NULL; rp = rp->ai_next){
        if(!rp->ai_family == AF_INET && !rp->ai_family == AF_INET6)
            continue;

        addr_tmp = eload_address_new(rp);
        //addr_tmp = eload_address_new(rp->ai_family, rp->ai_socktype, 
        //        rp->ai_protocol, rp->ai_addr, rp->ai_addrlen);
        if(!addr_tmp) goto error;
        addr_tmp->next = addr_list;
        addr_list = addr_tmp;
    }
    freeaddrinfo(result);
    addr_ctx->eaddr = addr_list;
    return 0;
error:
    freeaddrinfo(result);
    eload_address_free(addr_list);
    return -1;
}



eload_addr_t *eload_create_servers(uint32_t num)
{
    eload_addr_t *s = NULL;
    uint32_t count = num;
    if(count == 0){
        count = max_http_servers;
    }
    s = calloc(count, sizeof(eload_addr_t));
    if(!s){
        fprintf(stderr, "%s: out of mem: %d", __func__, count);
        return NULL;
    }
    max_http_servers = count;

    return s;
}

static void eload_destory_servers()
{
    if(!http_servers)return;
    uint32_t i = 0;
    for(i = 0; i < max_http_servers; i++){
        if(http_servers[i].hostname) free(http_servers[i].hostname);
        if(http_servers[i].uri) free(http_servers[i].uri);
        if(http_servers[i].url) free(http_servers[i].url);
        if(http_servers[i].eaddr) eload_address_free(http_servers[i].eaddr);
        if(http_servers[i].payload) free(http_servers[i].payload);
    }
    free(http_servers);
}


static int 
eload_set_payload(eload_addr_t *server, char *filepath, char *encode)
{
    struct stat buffer;
    char header[MAX_BUF_LEN];
    uint8_t hascode = 0;
    uint16_t head_len;
    if(!server) return -1;
    
    server->method = MTD_GET;
    if(filepath){
        server->method = MTD_POST;
        if(encode) hascode = 1;

        if(stat(filepath, &buffer) < 0){
            fprintf(stderr, "[Error] %s\n", strerror(errno));
            return -1;
        }
        head_len = snprintf(header, sizeof(header), 
                                        HTTP_POST_TEMP, 
                                        server->uri, 
                                        server->hostname, 
                                        hascode ? encode : HTTP_CONTENT_TEXT,
                                        buffer.st_size); 
        server->payload_len = head_len + buffer.st_size;
    } else {
        server->method = MTD_GET;
        head_len = snprintf(header, sizeof(header), 
                                        HTTP_GET_TEMP,
                                        server->uri, 
                                        server->hostname);
        server->payload_len = head_len;
    }
    if(head_len > sizeof(header)){
        fprintf(stderr, "[BUG] %s: http header too long\n", __func__);
        return -1;        
    }
    
    server->payload = calloc(server->payload_len, sizeof(uint8_t));
    if(!server->payload){
        fprintf(stderr, "%s: out of mem\n", __func__);
        return -1;
    }
    memcpy(server->payload, header, head_len);
    
    if(filepath){
        FILE *file = fopen(filepath, "r");
        if(!file){
            fprintf(stderr, "[Error]failed to open payload file: %s\n", strerror(errno));
            return -1;
        }
        if(fread(server->payload+head_len, sizeof(uint8_t), buffer.st_size, file) != (size_t)buffer.st_size){
            fprintf(stderr, "[Error]failed to read %s\n", filepath);
            return -1;
        }
        fclose(file);
    }
    return 0;
}

static int eload_url_parser(char *urls, char *paths, char *code, uint32_t count)
{
    if(!urls) return -1;
        
    http_servers = eload_create_servers(count);
    if(http_servers == NULL)
        return -1;

    if(http_config_init() != 0)
        return -1;

    uint32_t i = 0;
    for(i = 0; i < max_http_servers; i++){
        //TODO 解析url列表
        http_servers[i].url = strdup(urls);
        http_servers[i].url_len = strlen(http_servers[i].url);
        if(http_url_is_vaild(http_servers[i].url, http_servers[i].url_len) != 0)
            break;
        http_servers[i].hostname = http_get_host(http_servers[i].url, 
            http_servers[i].url_len, &http_servers[i].host_len);
        if(http_servers[i].hostname == NULL || http_servers[i].host_len == 0)
            break;

        http_servers[i].uri = http_get_uri(http_servers[i].url, 
            http_servers[i].url_len, &http_servers[i].uri_len);

        http_servers[i].protocol = http_get_protocol(http_servers[i].url, 
            http_servers[i].url_len);
        if(http_servers[i].protocol == PROTO_ERROR) break;
        
        http_servers[i].port = http_get_port(http_servers[i].url, 
            http_servers[i].url_len);
        if(!http_servers[i].port)break;

        if(eload_address_lookup(&http_servers[i]) != 0)
            break;

        if(eload_set_payload(&http_servers[i], paths, code) != 0)
            break;

    }
    if(i != max_http_servers){
        fprintf(stderr, "[Error] invalid url: %s\n", http_servers[i].url);
        return -1;
    }
    return 0;
}


static int eload_http_parser(eload_conn *conn_ctx, uint8_t *data, uint32_t data_len)
{
    assert(data != NULL || data_len > 0);
#if 0
    uint32_t content_recv = 0;  /* 当前接收的http content长度 */

    content_recv = http_status_parser(data, data_len, &conn_ctx->http_status, 
        &conn_ctx->http_content_length);
    
    if(content_recv != 0 && conn_ctx->http_content_length){
         conn_ctx->http_content_recv += content_recv;
    }
    if(conn_ctx->http_content_length == 0 || 
        conn_ctx->http_content_recv == conn_ctx->http_content_length){
        return HTTP_STATUS_DONE;
    }
    return HTTP_STATUS_NONE;
#else
    return conn_ctx->http_status = http_status_parser(data, data_len);
#endif
}

static inline void eload_conn_status_update(eload_conn *conn_ctx, int state)
{
    conn_ctx->tcp_status = state;
}

static int eload_handle_error(eload_conn *ctx)
{
    int s, err = 0;
    socklen_t len;
    if(getsockopt(ctx->fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0){
        if(err){
            //fprintf(stderr, "[Error] %s %d\n", strerror(err), err);
            return -1;
        }
    }
    return 0;
}

static int eload_event_update(eload_conn *ctx, int einstance, 
         int event, int op)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    
    ev.data.ptr = ctx;
    if(epoll_event_update(einstance, &ev, ctx->fd, event, op) != 0){
        return -1;
    }
    return 0;
}

static void eload_handle_event(int ep, struct epoll_event *ev, conn_mgt *timelist)
{
    eload_conn *conn_ctx = (eload_conn *)ev->data.ptr;
    int ret = -1;

    assert(conn_ctx != NULL);
    int events = ev->events;
    if(events & EPOLLERR || events & EPOLLHUP){ /* something error */
        if(eload_handle_error(conn_ctx) != 0){
            eload_conn_delete(timelist, conn_ctx, TCP_STAT_ERROR);
        }
    }else if(events & EPOLLOUT){ /* 缓冲区空闲，可以写 */
        if(conn_ctx->tcp_status == TCP_STAT_CONN){
            if(eload_handle_write(conn_ctx) == PROC_ERROR){
                eload_conn_delete(timelist, conn_ctx, TCP_STAT_ERROR);
                return;
            }
            if(eload_event_update(conn_ctx, ep, EPOLLIN, EPOLL_CTL_MOD) < 0){
                eload_conn_delete(timelist, conn_ctx, TCP_STAT_ERROR);
                return;
            }
            eload_conn_status_update(conn_ctx, TCP_STAT_READ);
        }else{
            fprintf(stderr, "[BUG] %s: EPOLLOUT [%d] conn't be here!!\n", 
                __func__, conn_ctx->tcp_status);
            abort();
        }
    }else if(events & EPOLLIN){  /* 有数据可读 */
        if(conn_ctx->tcp_status == TCP_STAT_READ){
            if((ret = eload_handle_read(conn_ctx)) == PROC_ERROR){
                eload_conn_delete(timelist, conn_ctx, TCP_STAT_ERROR);
                return;
            }
            /* TODO: 解析http报文，完全接收完后再关闭 */
            if(ret == PROC_CLOSED){
                eload_conn_delete(timelist, conn_ctx, TCP_STAT_CLOSED);
            }
        }else{
            fprintf(stderr, "[BUG] %s: EPOLLIN [%d] conn't be here!!\n", 
                    __func__, conn_ctx->tcp_status);
            abort();
        }
    }
    
}


static long long
eload_delta_timeval(struct timeval* finish, struct timeval* start)
{
    long long delta_secs = finish->tv_sec - start->tv_sec;
    long long delta_usecs = finish->tv_usec - start->tv_usec;
    return delta_secs * (long long) ELOAD_USEC_PER_SEC + delta_usecs;
}


static unsigned long long 
eload_time_dealt(struct timeval *end, struct timeval *start)
{
    return (ELOAD_USEC_PER_SEC*(end->tv_sec - start->tv_sec) + end->tv_usec - start->tv_usec);
}

static inline void eload_timenow(struct timeval *tv)
{
    gettimeofday(tv, NULL);
}

static void eload_date(char *buf, size_t buf_size, struct timeval *ts)
{
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64];
    
    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buf, buf_size, "%s", tmbuf);
    if(ts){
        ts->tv_sec = tv.tv_sec;
        ts->tv_usec = tv.tv_usec;
    }
}

static float eload_clock()
{
    return (float)clock()/CLOCKS_PER_SEC;
}

static conn_mgt * eload_conn_timeout_new()
{
    conn_mgt *list = malloc(sizeof(conn_mgt));
    if(!list){
        fprintf(stderr, "[Error] out of mem for create timeout list\n");
        return NULL;
    }
    list->head = list->tail = NULL;
    return list;
}

static void eload_conn_timeout_free(conn_mgt *list)
{
    if(list) free(list);
}


static void eload_conn_delete(conn_mgt *list, eload_conn *node, int status){
    if(list->head== NULL || node->fd == -1) return;
    
    if(node == list->head){  /* 头 */
        list->head = list->head->next;
        if(list->head){
            list->head->prev = NULL;
        }else{
            list->tail = NULL;
        }
    }else if(node == list->tail){   /* 尾 */
        list->tail = list->tail->prev;
        list->tail->next = NULL;
    }else{
        node->next->prev = node->prev;
        node->prev->next = node->next;
    }

    node->prev = NULL;
    node->next = NULL;

    eload_handle_disconn(node, status);
}

/*
* 头部新增
*/
static inline void eload_conn_timeout_add(conn_mgt *list, eload_conn *node)
{
    assert(node->fd != -1);

    if(list->head == NULL){
        node->next = NULL;
        node->prev = NULL;
        list->head = node;
        list->tail = node;
    }else{
        node->prev = NULL;
        node->next = list->head;
        list->head->prev = node;
        list->head = node;
    }
}


/*
* 尾部连接超时关闭删除
*/
static void eload_conn_timeout_remove(conn_mgt *list)
{
    eload_conn *tmp = NULL;

    assert(list->tail != NULL);

    tmp = list->tail;
    if(tmp->prev == NULL){ /* only one */
        list->head = NULL;
        list->tail = NULL;
    }else{
        list->tail = list->tail->prev;
        list->tail->next = NULL;
    }
    tmp->prev = NULL;
    tmp->next = NULL;   
    eload_handle_disconn(tmp, TCP_STAT_TIMMEOUT);
    //fprintf(stderr, "[DEBUG] timeout remove %p  status: %s\n", 
    //    tmp, tcpstat_to_string[tmp->tcp_status].str);
}

static uint32_t eload_conn_timeout_check(conn_mgt *list)
{
#define EPOLL_RES_TIME_OUT (30*ELOAD_USEC_PER_SEC)  /* 30s 超时 */

    uint8_t timeout = 1;
    uint32_t count = 0;
    if(list->tail){
        struct timeval now;
        eload_timenow(&now);
        while(list->tail && timeout){
            switch(list->tail->tcp_status){
                case TCP_STAT_READ:/* 等待服务器响应超时       */
                    if(eload_time_dealt(&now, &list->tail->req_at) < EPOLL_RES_TIME_OUT)
                        timeout = 0;
                    break;
                case TCP_STAT_WRITE:
                case TCP_STAT_CONN:/* 尝试连接超时 */
                    if(eload_time_dealt(&now, &list->tail->conn_at) < EPOLL_RES_TIME_OUT)
                        timeout = 0;
                    break;
                case TCP_STAT_CLOSED:
                     if(eload_time_dealt(&now, &list->tail->close_at) < EPOLL_RES_TIME_OUT)
                        timeout = 0;
                     break;
                default:
                    //fprintf(stderr, "[BUG?]other stat[%d] timeout, whould be here?\n", 
                    //        list->tail->tcp_status);
                    break;                
            }
            if(timeout){
                if(list->tail->tcp_status < TCP_STAT_CLOSED){
                    count++;  /* 只统计正常连接超时 */
                }
                eload_conn_timeout_remove(list);  
            }
        }
    }
    return count;
}

/*
* 头插入法 超时链
* 保持头部第一个的时间是最新的
* 尾部为最旧的
*/
static inline void eload_conn_timeout_update(conn_mgt *list, eload_conn *node)
{
    eload_conn *tmp = NULL;
    if(list->head == NULL || node == NULL || node->fd == -1) return;

    if(node != list->head){
        assert(list->tail != NULL);
        if(node == list->tail){ /* 尾部 */
            list->tail = node->prev;
            list->tail->next = NULL;
        }else{  /* 中部 */
            node->next->prev = node->prev;
            node->prev->next = node->next;
        }
        node->prev = NULL;
        node->next = list->head;
        list->head->prev = node;
        list->head = node;
    }
    
}



static int eload_handle_conn(eload_conn *conn_ctx, int ephandler)
{
    int i, sfd, ret;
    struct sockaddr_in addr;
    eload_addr *tmp;

    srand(0);
    uint16_t key = rand();
    conn_ctx->server_index = 0;
    if(max_http_servers > 1)
        conn_ctx->server_index = (key % max_http_servers); /* 随机选择一个url连接 */
    
    for(tmp = http_servers[conn_ctx->server_index].eaddr; 
            tmp != NULL; tmp = tmp->next){
        //if(!(tmp->mask == 0 || key % tmp->mask == 0)) continue; 
            
        sfd = socket(tmp->sock_family, tmp->sock_type, tmp->sock_protocol);
        if (sfd == -1){
            fprintf(stderr, "[Error] socket error:%s\n",strerror(errno));
            continue;
        }
        
        bzero(&addr, sizeof(addr));
        addr.sin_family = tmp->sock_family;
        addr.sin_port = htons(http_servers[conn_ctx->server_index].port);
        if(inet_pton(addr.sin_family, tmp->ip_str, &addr.sin_addr) < 0){
            fprintf(stderr, "[Error] connect error:%s\n",strerror(errno));
            close(sfd);
            //tmp->mask = 1;
            continue;
        }
        /* 
        * 非堵塞socket，connnect、read、write，全都是非堵塞处理
        */
        epoll_set_nonblock(sfd);
        conn_ctx->fd = sfd;

        eload_timenow(&conn_ctx->conn_at);
        eload_event_update(conn_ctx, ephandler, EPOLLIN|EPOLLOUT, EPOLL_CTL_ADD);        
        ret = connect(sfd, (struct sockaddr *)&addr, sizeof(addr));
        if(ret == 0){
            /*下一步准备进行发送数据*/
            eload_conn_status_update(conn_ctx, TCP_STAT_WRITE);
            //fprintf(stderr, "[DEBUG] connected %d\n", sfd);
            break;
        }else if (ret < 0){
            /* 三次握手进行中，连接完成会在epoll中检测 */
            if(errno == EINPROGRESS){
                //fprintf(stderr, "[DEBUG] connecting %d\n", sfd);
                eload_conn_status_update(conn_ctx, TCP_STAT_CONN);
                break;
            }
            fprintf(stderr, "[Error] connect error:%s\n",strerror(errno));
            close(sfd);
            continue;
        }
   }
   if(tmp == NULL){
        conn_ctx->fd = -1;
   }
   return 0;
}

static void eload_handle_disconn(eload_conn *conn_ctx, int status)
{
    if(conn_ctx->fd != -1){
        eload_timenow(&conn_ctx->close_at);
        close(conn_ctx->fd);
        conn_ctx->fd = -1;
        eload_conn_status_update(conn_ctx, status);
    }
}

/* 读取报文解析HTTP状态 */
static int eload_handle_read(eload_conn *conn_ctx)
{
    uint8_t buf[MAX_BUF_LEN];
    int stat = 0;
    
    assert(conn_ctx->tcp_status == TCP_STAT_READ);
    
#ifdef USE_SSL
    //TODO
#endif

    //conn_ctx->res_at = eload_clock();
    eload_timenow(&conn_ctx->res_at);
    int ret = 0;
    while(1){
        ret = recv(conn_ctx->fd, buf, sizeof(buf), 0);
        if(ret == 0){
            stat = PROC_CLOSED;
            break;
        }else if(ret < 0){
            if(errno == EAGAIN){
                stat = PROC_NODO;
                break;
            }
            if(errno == EINTR)
                continue;
            fprintf(stderr, "%s: [Error] in read: %s\n", __func__, strerror(errno));
            stat = -1;
            break;
        }else if(ret > 0) {

 #if 0       
            if(eload_http_parser(conn_ctx, buf, ret) == HTTP_STATUS_DONE){
                /* TODO 数据已经接收完*/
                stat = 0;
                break;
            }   
 #else
             if(conn_ctx->http_status == HTTP_STATUS_NONE){
                // only one shoot
                eload_http_parser(conn_ctx, buf, ret);
            }
 #endif
            // else do northing
            if(ret < MAX_BUF_LEN){
                stat = PROC_NODO;
                break;
            }
        }
        
    }
    return stat;
}

static int eload_handle_write(eload_conn *conn_ctx)
{
    assert(conn_ctx->tcp_status == TCP_STAT_CONN || conn_ctx->tcp_status == TCP_STAT_WRITE);
    
    int ret;
    const uint32_t sever_idx = conn_ctx->server_index;
    const uint8_t *request_payload = http_servers[sever_idx].payload;
    int data_len = http_servers[sever_idx].payload_len;
    int stat = PROC_NODO;

    uint8_t buf[MAX_BUF_LEN];

#ifdef USE_SSL
    //TODO SSL
#endif
     
    eload_timenow(&conn_ctx->req_at);
    int send = 0;
    while(data_len){
        ret = write(conn_ctx->fd, request_payload+send, data_len);
        if(ret <= 0){
            if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
                continue;
            fprintf(stderr, "[Error] %s: while sending: %s\n", __func__, strerror(errno));
            stat = PROC_ERROR;
            break;
            
        }
        send += ret;
        data_len -= ret;
    }   
    return stat;
}

static void eload_handle_signal(int signum)
{
    if(signum == SIGRTMIN || signum == SIGINT){
        eload_state = ELOAD_DONE;
    }
    return;
}


static void eload_signal_setup()
{
    signal(SIGINT,eload_handle_signal);
    signal(SIGTERM,eload_handle_signal);
}


void eload_thread_setup(eload_thv *thread_data, void* (*do_task)(void *))
{
    pthread_attr_t attr;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    pthread_create(&thread_data->tid, &attr, do_task, thread_data);
}

static int eload_thval_init(eload_ctx *ctx)
{
    int i = 0;
    ctx->thrdata = calloc(max_thread, sizeof(eload_thv));
    if(!ctx->thrdata){
        fprintf(stderr, "%s: alloc thread data faild\n", __func__);
        return -1;
    }
     /*如果能均分就平均分配，不然就最后一个分多点*/
    uint32_t avg_connections = max_connections / max_thread;   //平均连接数
    if(0 == max_connections - avg_connections*max_thread){
        for(i = 0; i < max_thread; i++)
            ctx->thrdata[i].max_connections = avg_connections;

    }else{
        for(i = 0; i < max_thread - 1; i++)
            ctx->thrdata[i].max_connections = avg_connections;
        
        ctx->thrdata[max_thread-1].max_connections = 
            max_connections - (max_thread-1) * avg_connections;
    }

    /* 并发数一样的方式处理 */
    uint32_t per_rate = per_connections / max_thread;
    if(0 == per_connections - per_rate*max_thread){
        for(i = 0; i < max_thread; i++)
            ctx->thrdata[i].per_connections = per_rate;
    }else{
        for(i = 0; i < max_thread - 1; i++)
            ctx->thrdata[i].per_connections = per_rate;
        
        ctx->thrdata[max_thread-1].per_connections = 
            per_connections - (max_thread-1)*per_rate;
    }    
    
    for(i = 0; i < max_thread; i++){
        ctx->thrdata[i].conn_slot = 
            calloc(ctx->thrdata[i].max_connections, sizeof(eload_conn));
        if(!ctx->thrdata[i].conn_slot){
            fprintf(stderr, "%s: alloc failed for conn slot [%d]", __func__, 
                    ctx->thrdata[i].max_connections * sizeof(eload_conn));
            return -1;
        }
    }
    
    for(i = 0; i < max_thread; i++)
        eload_thread_setup(&ctx->thrdata[i], eload_woker);

    return 0;
}


static int eload_thval_deinit(eload_ctx *ctx)
{
    uint8_t i;

    if(!ctx->thrdata) return;
    for(i = 0; i < max_thread; i++){
        while(!ctx->thrdata[i].done)usleep(5);
        if(ctx->thrdata[i].conn_slot)
            free(ctx->thrdata[i].conn_slot);
        pthread_join(ctx->thrdata[i].tid, NULL);
    }
    free(ctx->thrdata);
    ctx->thrdata = NULL;
}


#define EPOLL_TIMEOUT_USEC 3  /* epoll等待时长，该参数和并发有紧密联系 */

static void* eload_woker(void *arg)
{
    eload_thv *thctx = (eload_thv *)arg;
    const uint32_t conn_free = thctx->max_connections;
    const uint32_t conn_rate = thctx->per_connections; 
    uint32_t conn_active = 0;                            /* 正在活动的连接--并发 */
    uint32_t conn_done = 0;                              /* 所有操作都已完成 */
    uint32_t conn_used;                              /* 已使用的连接数 */
    uint32_t conn_err = 0;
    uint32_t i, tmp, conn_timeout = 0;
    eload_conn *conn_ctx;
    conn_mgt *timelist;
    int n, nfds;
    
    int ephandler = epoll_create(conn_rate*2);     
    if(ephandler == -1){
        fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
        goto end;
    }
    struct epoll_event *conn_ev = calloc(conn_rate*2, sizeof(struct epoll_event));
    if(!conn_ev){
        fprintf(stderr, "%s: out of mem for create epoll_event\n", __func__);
        goto end;
    }
    timelist = eload_conn_timeout_new();
    if(!timelist) goto end;
    
    while(eload_state == ELOAD_WAITING);

    eload_timenow(&thctx->start_at);
    i = conn_used = 0;
    while(eload_state == ELOAD_RUNING){
        for(i = conn_used; conn_active < conn_rate && i < conn_free; i++){
            /*每次只创建conn_rate个链接*/
            if(thctx->conn_slot[i].tcp_status == TCP_STAT_FREE){
                conn_used++;
                if(eload_handle_conn(&thctx->conn_slot[i], ephandler) != 0){
                    conn_err++;
                    continue;
                }
                conn_active++;
                /* 连接成功，直接发数据 */
                if(thctx->conn_slot[i].tcp_status == TCP_STAT_WRITE){
                    if(eload_handle_write(&thctx->conn_slot[i]) < 0){
                        eload_conn_delete(timelist, &thctx->conn_slot[i], TCP_STAT_ERROR);
                        conn_err++;
                        conn_active--;
                        continue;
                    }
                    eload_event_update(&thctx->conn_slot[i], ephandler, 
                        EPOLLIN, EPOLL_CTL_MOD);
                    eload_conn_status_update(&thctx->conn_slot[i], TCP_STAT_READ);
                }
                eload_conn_timeout_add(timelist, &thctx->conn_slot[i]);
                break;
            }
        }
        conn_used = i; /* 缓存最后一次的记录 */

        nfds = epoll_wait(ephandler, conn_ev, conn_rate*2, EPOLL_TIMEOUT_USEC);
        if(nfds > 0){
            for(n = 0; n < nfds; n++){
                conn_ctx = conn_ev[n].data.ptr;
                eload_handle_event(ephandler, &conn_ev[n], timelist);
                if(conn_ctx && conn_ctx->tcp_status >= TCP_STAT_CLOSED){
                    switch(conn_ctx->tcp_status){
                        case TCP_STAT_CLOSED:
                            conn_done++;
                            conn_active--;
                            break;
                        case TCP_STAT_ERROR:
                            conn_err++;
                            conn_active--;
                            break;
                    }
                }
                eload_conn_timeout_update(timelist, conn_ctx);
            }
        }else if (nfds == 0){
            //fprintf(stderr, "[DEBUG] epoll_wait timeout\n");
        }else{
            fprintf(stderr, "[Error] epoll_wait: %s\n", strerror(errno));
        }
        tmp = eload_conn_timeout_check(timelist);  /* 检测超时关闭 */
        conn_timeout += tmp;
        conn_active -= tmp;

        thctx->conn_timeout = conn_timeout;
        thctx->conn_active = conn_active;
        thctx->conn_done = conn_done;
        thctx->conn_err = conn_err;
        
        if(conn_active == 0 && conn_used >= conn_free)
            break;
    }
    eload_timenow(&thctx->end_at);
    
    for(i = 0; i < conn_used; i++)
        eload_handle_disconn(&thctx->conn_slot[i], TCP_STAT_FREE);
end:
    eload_conn_timeout_free(timelist);
    if(conn_ev) free(conn_ev);
    
    thctx->done = 1;
    return arg;
}


static void eload_result(eload_ctx *ctx)
{
    int counter[TCP_STAT_MAX+1] = {0};
    uint32_t t, i;

    uint32_t isucc = 0;
    unsigned long min_conn = ULONG_MAX;
    unsigned long  max_conn = 0;
    float  avg_conn = 0;
    unsigned long  total_conn = 0;
    unsigned long  conn = 0;

    unsigned long  min_wait = ULONG_MAX;
    unsigned long  max_wait = 0;
    float  avg_wait = 0;
    unsigned long  total_wait = 0;
    unsigned long  wait = 0;

    unsigned long  min_proc = ULONG_MAX;
    unsigned long  max_proc = 0;
    float avg_proc = 0;
    unsigned long  total_proc = 0;
    unsigned long  proc = 0;

    unsigned long  min_total = ULONG_MAX;
    unsigned long  max_total = 0;
    float avg_total = 0;
    unsigned long  total_total = 0;
    unsigned long  total = 0;
  
    for(t = 0; t < max_thread; t++){
        for(i = 0; i < ctx->thrdata[t].max_connections; i++){
            eload_thv *thv = &ctx->thrdata[t];
            counter[thv->conn_slot[i].tcp_status]++;
            http_status_buckets[thv->conn_slot[i].http_status]++;
            if(thv->conn_slot[i].tcp_status == TCP_STAT_CLOSED){

                /* 连接耗时 */
                conn = eload_time_dealt(&thv->conn_slot[i].req_at, &thv->conn_slot[i].conn_at);
                total_conn += conn;
                if(conn > max_conn) max_conn = conn;
                if(min_conn > conn) min_conn = conn;

                /* 等待服务器响应耗时 */
                wait = eload_time_dealt(&thv->conn_slot[i].res_at, &thv->conn_slot[i].req_at);
                total_wait += wait;
                if(wait > max_wait) max_wait = wait;
                if(min_wait > wait) min_wait = wait;

                /* 数据传输、处理耗时 */
                proc = eload_time_dealt(&thv->conn_slot[i].close_at, &thv->conn_slot[i].res_at);
                total_proc += proc;
                if(proc > max_proc) max_proc = proc;
                if(min_proc  > proc) min_proc = proc;

                /* 完整连接总耗时 */
                total =  eload_time_dealt(&thv->conn_slot[i].close_at, &thv->conn_slot[i].conn_at);
                total_total += total;
                if(total > max_total) max_total = total;
                if(min_total > total) min_total = total;

                isucc++;
            }
            
        }
    }
    if(isucc != 0){
        avg_conn = total_conn*1.0 / isucc / 1000;
        avg_wait = total_wait*1.0 / isucc / 1000;
        avg_proc = total_proc*1.0 / isucc / 1000;
        avg_total = total_total*1.0 / isucc / 1000;
    }else{
        min_conn = min_proc = min_wait = min_total = 0;
    }
    
    for(i = TCP_STAT_FREE; i < TCP_STAT_MAX; i++)
        if(counter[i]) printf("tcp status %s \t%d\n",
            tcpstat_to_string[i].str, counter[i]);

    for(i = 0; i < sizeof(http_status_buckets)/sizeof(int); i++)
        if(http_status_buckets[i]) 
            printf("http status %d\t\t%d\n", i, http_status_buckets[i]);
        
    printf("\nConnection Time(ms):\n");
    printf("\t    min   \tmean \tmax\n");
    printf("Connect:   %.3f      %.3f \t%.3f\n", min_conn*1.0/1000, avg_conn, max_conn*1.0/1000);
    printf("Waiting:   %.3f      %.3f \t%.3f\n", min_wait*1.0/1000, avg_wait, max_wait*1.0/1000);
    printf("Process:   %.3f      %.3f \t%.3f\n", min_proc*1.0/1000, avg_proc, max_proc*1.0/1000);
    printf("Total:     %.3f      %.3f \t%.3f\n", min_total*1.0/1000, avg_total, max_total*1.0/1000);
}


static eload_ctx *eload_ctx_new()
{
    eload_ctx *ctx = malloc(sizeof(eload_ctx));
    if(!ctx){
        fprintf(stderr, "%s: out of mem\n", __func__);
        return NULL;
    }
    memset(ctx, 0, sizeof(eload_ctx));

    return ctx;
}

static void eload_ctx_free(eload_ctx *ctx)
{
    if(ctx){
        eload_thval_deinit(ctx);
        free(ctx);
    }
}


static int eload_init(eload_ctx *ctx)
{
    uint32_t i;
    if(eload_rlimit_config() != 0)
        return -1;
  
    eload_signal_setup();    
    return eload_thval_init(ctx);
}

static void eload_destory(eload_ctx *ctx){    
    http_config_free();
    eload_destory_servers();
    eload_ctx_free(ctx);
}


static double eload_get_timetoken_sec(eload_ctx *ctx)
{
    struct timeval start_tv = ctx->thrdata[0].start_at;
    struct timeval finish_tv = ctx->thrdata[0].end_at;
    uint8_t i;
    for(i = 1; i < max_thread; i++){
        if(ctx->thrdata[i].start_at.tv_sec < start_tv.tv_sec || 
                (ctx->thrdata[i].start_at.tv_sec == start_tv.tv_sec &&
                ctx->thrdata[i].start_at.tv_usec < start_tv.tv_usec))
            start_tv = ctx->thrdata[i].start_at;

        if(ctx->thrdata[i].end_at.tv_sec > finish_tv.tv_sec || 
                (ctx->thrdata[i].end_at.tv_sec == finish_tv.tv_sec &&
                ctx->thrdata[i].end_at.tv_usec > finish_tv.tv_usec))
            finish_tv = ctx->thrdata[i].end_at;        
    }
    return (double)eload_time_dealt(&finish_tv, &start_tv)*1.0/ELOAD_USEC_PER_SEC;
}

static void eload_run(eload_ctx *ctx)
{
    uint32_t count = 0, succ_per, succ_max = 0, succ_totall = 0;
    uint32_t succ_min = max_connections;
    uint32_t conn_free;
    uint32_t conn_err;
    uint32_t conn_timeout;
    uint32_t conn_done;    /* 完成http请求的连接数 */
    uint32_t last_done = 0;
    uint16_t conn_active;
    uint8_t i = 0, finish;
    char date_str[64];
    struct timeval start_tv, finish_tv;
    eload_date(date_str, sizeof(date_str), &start_tv);
    fprintf(stderr, "%s: eload start\n", date_str); 
    
    eload_state = ELOAD_RUNING;  //free waiting child
    while(1){
        //TODO：运行时的连接状态统计
        conn_free = 0;
        conn_err = 0;
        conn_done = 0;
        conn_active = 0;
        finish = 0;
        conn_timeout = 0;
        sleep(1);
        for(i = 0; i < max_thread; i++){
			conn_timeout += ctx->thrdata[i].conn_timeout;
            conn_err += ctx->thrdata[i].conn_err;
            conn_done += ctx->thrdata[i].conn_done;
            conn_active += ctx->thrdata[i].conn_active;
            if(ctx->thrdata[i].done)finish++;
        }
        conn_free = max_connections - conn_timeout -
                    conn_err - conn_done - conn_active;
        eload_date(date_str, sizeof(date_str), &finish_tv);

        succ_per = conn_done - last_done;
        fprintf(stderr, "%s# succ: %d active: %d  finish: %d"
                        "  free: %d  timeout: %d  error: %d\n",
                    date_str, succ_per, conn_active, conn_done,
                    conn_free, conn_timeout, conn_err);
        
        last_done = conn_done;
        if(succ_min > succ_per) succ_min = succ_per;
        if(succ_max < succ_per) succ_max = succ_per;
        succ_totall += succ_per;
        count++;
        
        if(finish == max_thread) break;
    }
    double loop_time = eload_get_timetoken_sec(ctx);
    printf("\n\nOverview:\n");
    printf("Time taken(s):   %.3f\n", loop_time);
    eload_result(ctx);
    if(count){
        printf("\nConnection succ(c/s):  %.3f\n\n", conn_done*1.0/loop_time);
    }
    
}

int main(int argc, char **argv)
{
    eload_ctx *ctx = eload_ctx_new();
    if(!ctx){
        return -1;
    }
    if(eload_options_parser(ctx, argc, argv) != 0){
        eload_usage();
        goto end;
    }
    if(eload_init(ctx) != 0){
        goto end;
    }
    eload_run(ctx);
    
end:    
    eload_destory(ctx);
    return 0;
}
