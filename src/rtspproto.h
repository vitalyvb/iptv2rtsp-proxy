#ifndef RTSPPROTO_H
#define RTSPPROTO_H

#include "global.h"

typedef uint64_t rtsp_session_id;

int cook_rtsp_session_id(char *dstbuf, int bufsize, rtsp_session_id *sess_id);
int parse_rtsp_session_id(char *buf, rtsp_session_id *sess_id);

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


struct rtsp_requested_stream {
    // uri parts
    char hostname[64];
    char path[64];
    char query[64];

    // parsed
    char category[16];
    char group[32];
    char port[8];
};

static struct rtsp_requested_stream *alloc_requested_stream();
void free_requested_stream(struct rtsp_requested_stream *s);
struct rtsp_requested_stream *parse_requested_stream(char *in_text, int len);

#endif /* RTSPPROTO_H */
