#include "util-epoll.h"
#include <unistd.h>
#include <fcntl.h>


void epoll_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 1){
        fprintf(stderr, "set_nonblock GET fcntl: %s", strerror(errno));
        return;
    }
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0){
        fprintf(stderr, "set_nonblock SET fcntl: %s", strerror(errno));
        return;
    }
}

int epoll_event_update(int ehandler, struct epoll_event *ev, int fd, int events, int op)
{
    assert(ev != NULL);
    ev->events = events;    
    if(epoll_ctl(ehandler, op, fd, ev) && errno != EEXIST){
        fprintf(stderr, "epoll_ctl faild: %s", strerror(errno));
        return -1;
    }
    return 0;
}

