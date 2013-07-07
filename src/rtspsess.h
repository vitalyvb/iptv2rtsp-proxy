#ifndef RTSPSESS_H
#define RTSPSESS_H

#include "global.h"
#include "rtsp.h"
#include "ht.h"
#include "url.h"
#include "rtspproto.h"

struct rtsp_session {
    struct hashable hh_ssrc;
    struct hashable hh_sess;

    client_session_id session_id;

    struct in_addr addr;
    uint16_t client_port_lo;
    uint16_t client_port_hi;

    int playing;

    struct rtsp_mpegio_streamer *streamer;

    int mpegio_client_id;

    uint32_t ssrc;

    ev_tstamp last_error_tstamp;
    int send_errors;

    ev_tstamp latest_activity;
    int rtcp_reported_packet_loss;
    int have_rtcp_reports;
};

struct rtsp_session *rtsp_setup_session(RTSP, struct in_addr *client_addr, struct rtsp_transport_descr *transp, struct url_requested_stream *rs);

struct rtsp_session *rtsp_session_alloc(RTSP);
void rtsp_session_free(struct rtsp_session *sess);

void rtsp_destroy_session(RTSP, struct rtsp_session *sess);
void rtsp_destroy_session_id(RTSP, client_session_id *session_id);

int rtsp_session_play(RTSP, struct rtsp_session *sess, struct url_requested_stream *rs);
int rtsp_session_pause(RTSP, struct rtsp_session *sess, struct url_requested_stream *rs);

void rtsp_session_rtcp_data(void *_rtsp, uint32_t ssrc, uint32_t interarrival_jitter, uint32_t cumulative_lost, int fraction_lost, uint32_t jitter);

#endif /* RTSPSESS_H */
