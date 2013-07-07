#ifndef HTTPSESS_H
#define HTTPSESS_H

#include "global.h"
#include "rtsp.h"
#include "ht.h"
#include "url.h"

struct http_session {
    struct hashable hh;

    client_session_id session_id;

    struct http_session *release_next;
    int closed;

    struct rtsp_mpegio_streamer *streamer;
    int mpegio_client_id;
};

struct http_session *http_session_alloc(RTSP);
void http_session_free(struct http_session *sess);
struct http_session *http_setup_session(RTSP, struct in_addr *client_addr, struct url_requested_stream *rs, int fd);
int http_session_play(RTSP, struct http_session *sess);
void http_session_destroy(RTSP, struct http_session *sess);
void http_session_release(RTSP, struct http_session *sess);

int http_session_play(RTSP, struct http_session *sess);

#endif /* HTTPSESS_H */
