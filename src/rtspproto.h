#ifndef RTSPPROTO_H
#define RTSPPROTO_H

#include "global.h"
#include "url.h"

int cook_client_session_id(char *dstbuf, int bufsize, client_session_id *sess_id);
int parse_client_session_id(char *buf, client_session_id *sess_id);

struct rtsp_transport_descr {
    char transport[16];

    int unicast;
    int multicast;

    char destination[64];

    int client_port_lo;
    int client_port_hi;

    int server_port_lo;
    int server_port_hi;

    uint32_t ssrc;
};

char *cook_transport_header(const struct rtsp_transport_descr *transp);
struct rtsp_transport_descr *alloc_transport_header();
void free_transport_header(struct rtsp_transport_descr *t);
struct rtsp_transport_descr *parse_transport_header(char *in_text, int len);

int cook_rtsp_rtp_info(char *dstbuf, int bufsize, struct url_requested_stream *rs, uint32_t rtp_seq);

#endif /* RTSPPROTO_H */
