#ifndef RTCP_H
#define RTCP_H

#include "global.h"

typedef void (*handle_rtcp_data)(void *param, uint32_t ssrc, uint32_t interarrival_jitter, uint32_t cumulative_lost, int fraction_lost, uint32_t jitter);

struct rtcp_handler {
    ev_io rtcp_input_watcher;
    int rtcp_fd;

    handle_rtcp_data handler;
    void *handler_param;
};

typedef struct rtcp_handler *RTCP;

int rtcp_setup(RTCP, handle_rtcp_data handler, void *param, struct in_addr *listen_addr, int listen_port);
void rtcp_destroy(RTCP);

#endif /* RTCP_H */
