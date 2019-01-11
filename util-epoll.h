#ifndef _UTIL_EPOLL_H_
#include "eload.h"
#include <sys/epoll.h>

void epoll_set_nonblock(int fd);
int epoll_event_update(int , struct epoll_event *, int , int , int);


#endif
