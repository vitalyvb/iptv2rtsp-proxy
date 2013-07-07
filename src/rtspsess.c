/* Copyright (c) 2012, Vitaly Bursov <vitaly<AT>bursov.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the author nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "ebb.h"
#include "jhash.h"

#define LOG_MODULE ("rtspsess")
#define LOG_PARAM (NULL)

#include "global.h"
#include "mpegio.h"
#include "utils.h"
#include "rtspsess.h"
#include "url.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

#define this (_this)
#define THIS RTSP _this

struct rtsp_session *rtsp_session_alloc(THIS)
{
    struct rtsp_session *sess;

    sess = xmalloc(sizeof(struct rtsp_session));
    memset(sess, 0 , sizeof(struct rtsp_session));

    sess->session_id = my_rand();

    ht_register_rtsp_sess(this, sess);
    return sess;
}

void rtsp_session_free(struct rtsp_session *sess)
{
    free(sess);
}

static uint32_t generate_ssrc(THIS)
{
    uint32_t ssrc;
    int iter = 100;

    while (iter-- > 0) {

	ssrc = my_rand();

	if (unlikely(ssrc == 0 || ssrc == 0xffffffff))
	    continue;

	if (unlikely(rtsp_session_find_by_ssrc(this, ssrc)))
	    continue;

	return ssrc;
    }

    log_error("generate_ssrc() failed");
    return 0;
}

struct rtsp_session *rtsp_setup_session(THIS, struct in_addr *client_addr, struct rtsp_transport_descr *transp, struct url_requested_stream *rs)
{
    struct rtsp_mpegio_streamer *streamer;
    struct rtsp_session *sess;
    struct mpegio_client *client;
    uint32_t rtp_seq;
    uint32_t ssrc;
    MPEGIO mpegio;

    if (transp->client_port_lo < 1024 || transp->client_port_lo > 65532 ||
	    transp->client_port_hi > 65534 ||
	    transp->client_port_lo > transp->client_port_hi){
	log_error("client specified strange port numbers");
	return NULL;
    }

    if (transp->client_port_hi - transp->client_port_lo > 9){
	log_warning("limiting client ports range");
	transp->client_port_hi = transp->client_port_lo + 9;
    }

    streamer = mpegio_streamer_prepare(this, client_addr, rs);
    if (streamer == NULL){
	return NULL;
    }
    mpegio = streamer->mpegio;

    ssrc = generate_ssrc(this);
    if (!ssrc){
	return NULL;
    }

    sess = rtsp_session_alloc(this);

    memcpy(&sess->addr, client_addr, sizeof(struct in_addr));
    sess->client_port_lo = transp->client_port_lo;
    sess->client_port_hi = transp->client_port_hi;
    sess->latest_activity = ev_now(evloop);

    sess->streamer = streamer;

    client = mpegio_client_create(mpegio);
    mpegio_client_setup_rtp(client, &sess->addr, sess->client_port_lo, ssrc);

    transp->ssrc = ssrc;

    mpegio_client_get_parameters(mpegio, client, &sess->mpegio_client_id, NULL, &rtp_seq);

    if (rtsp_session_set_ssrc_hash(this, sess, ssrc) < 0){
	log_error("session setup fail");
	return NULL;
    }

    log_info("session %llu, setup mpegio client id: %d ssrc: %08x seq: %d", sess->session_id, sess->mpegio_client_id, ssrc, rtp_seq);
    return sess;
}

void rtsp_destroy_session(THIS, struct rtsp_session *sess)
{
    struct rtsp_mpegio_streamer *streamer;
    MPEGIO mpegio;

    /* session must be removed from session hast table by now */

    streamer = sess->streamer;
    mpegio = streamer->mpegio;

    log_info("session %llu closed, client reported %d packets lost", sess->session_id, sess->rtcp_reported_packet_loss);

    rtsp_session_all_ssrc_hash_remove(this, sess);
    mpegio_clientid_destroy(mpegio, sess->mpegio_client_id);

    rtsp_session_free(sess);
}

void rtsp_destroy_session_id(THIS, client_session_id *session_id)
{
    struct rtsp_session *sess = rtsp_session_remove(this, session_id);

    if (sess){
	rtsp_destroy_session(this, sess);
    } else {
	log_warning("session to destroy is not found");
    }
}

int rtsp_session_play(THIS, struct rtsp_session *sess, struct url_requested_stream *rs)
{
    struct rtsp_mpegio_streamer *streamer;
    MPEGIO mpegio;

    streamer = mpegio_streamer_find(this, rs);

    if (streamer == NULL || streamer != sess->streamer){
	return -1;
    }

    mpegio = streamer->mpegio;

    mpegio_clientid_set_status(mpegio, sess->mpegio_client_id, MPEGIO_CLIENT_PLAY);

    return 0;
}

int rtsp_session_pause(THIS, struct rtsp_session *sess, struct url_requested_stream *rs)
{
    struct rtsp_mpegio_streamer *streamer;
    MPEGIO mpegio;

    streamer = mpegio_streamer_find(this, rs);

    if (streamer == NULL || streamer != sess->streamer){
	return -1;
    }

    mpegio = streamer->mpegio;

    mpegio_clientid_set_status(mpegio, sess->mpegio_client_id, MPEGIO_CLIENT_STOP);

    return 0;
}

void rtsp_session_rtcp_data(void *_rtsp, uint32_t ssrc, uint32_t interarrival_jitter, uint32_t cumulative_lost, int fraction_lost, uint32_t jitter)
{
    THIS = (RTSP)_rtsp;
    struct rtsp_session *sess;

    sess = rtsp_session_find_by_ssrc(this, ssrc);
    if (sess == NULL){
	log_debug("got rtcp report for unknown ssrc %08x", ssrc);
    } else {
	int jitter = interarrival_jitter;
	sess->latest_activity = ev_now(evloop);
	sess->rtcp_reported_packet_loss = cumulative_lost;
	sess->have_rtcp_reports = 1;

	if (fraction_lost || jitter >= WARN_JITTER_VALUE_RTCP_RR){
	    log_info("rtcp report: session %llu, loss rate since last report: %d/256, %d total, interarrival jitter: %d",
		    sess->session_id, fraction_lost, sess->rtcp_reported_packet_loss, jitter);
	}

    }
}

