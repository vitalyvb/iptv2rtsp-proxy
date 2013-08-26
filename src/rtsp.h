#ifndef RTSP_H
#define RTSP_H

#include "global.h"
#include "ebb.h"
#include "ht.h"
#include "url.h"
#include "rtcp.h"
#include "rtspproto.h"
#include "mpegio.h"

struct rtsp_session;
struct http_session;

struct rtsp_mpegio_streamer {
    struct hashable hh;

    struct mpegio_config config;
    MPEGIO mpegio;
    int id;
};

struct rtsp_server {
    ebb_server server;

    char server_id[32];
    struct in_addr listen_addr;
    uint16_t listen_port;
    uint16_t rtp_base_port;

    ebb_server http_server;
    uint16_t http_listen_port;
    char *http_congestion_ctl;

    int mpegio_latest_id;
    struct ht streamers_ht;
    int connection_counter;

    struct rtcp_handler rtcp_handler;
    int send_fd;

    ev_timer sess_timeout_watcher;

    struct ht http_sess_ht;
    struct http_session *http_sess_release;

    struct ht sess_id_ht;
    struct ht sess_ssrc_ht;

    struct ht_iterator sess_htiter;

    struct ht_iterator http_sess_htiter;

    int mpegio_bufsize;
    int mpegio_delay;
};

typedef struct rtsp_server *RTSP;

void ht_register_rtsp_sess(RTSP, struct rtsp_session *sess);

void ht_register_http_sess(RTSP, struct http_session *sess);
void http_session_delayed_destroy(RTSP, client_session_id sess_id);

struct rtsp_session *rtsp_session_find_by_ssrc(RTSP, uint32_t ssrc);

struct rtsp_session *rtsp_session_get(RTSP, client_session_id *session_id);
struct rtsp_session *rtsp_session_remove(RTSP, client_session_id *session_id);
int rtsp_session_set_ssrc_hash(RTSP, struct rtsp_session *sess, uint32_t ssrc);
int rtsp_session_all_ssrc_hash_remove(RTSP, struct rtsp_session *sess);


struct rtsp_mpegio_streamer *mpegio_streamer_find(RTSP, struct url_requested_stream *rs);
struct rtsp_mpegio_streamer *mpegio_streamer_prepare(RTSP, struct in_addr *client_addr, struct url_requested_stream *rs);

int rtsp_load_config(RTSP, dictionary *d);
RTSP rtsp_alloc();
int rtsp_init(RTSP);
void rtsp_cleanup(RTSP);

#endif /* RTSP_H */
