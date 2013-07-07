#ifndef URL_H
#define URL_H

#include "global.h"

#define REQUEST_URI_RTSP (1)
#define REQUEST_URI_HTTP (2)

struct url_requested_stream {
    // uri parts
    char hostname[64];
    char path[64];
    char query[64];

    // parsed
    char category[16];
    char group[32];
    char port[8];
};

static struct url_requested_stream *alloc_requested_stream();
void free_requested_stream(struct url_requested_stream *s);
struct url_requested_stream *parse_requested_stream(int type, char *in_text, int len);

#endif /* URL_H */
