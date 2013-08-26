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

#define LOG_MODULE ("httpsess")
#define LOG_PARAM (NULL)

#include "global.h"
#include "mpegio.h"
#include "utils.h"
#include "httpsess.h"
#include "url.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

#define this (_this)
#define THIS RTSP _this

struct http_session *http_session_alloc(THIS)
{
    struct http_session *sess;

    sess = xmalloc(sizeof(struct http_session));
    memset(sess, 0 , sizeof(struct http_session));
    sess->rtsp_server = this;

    sess->session_id = my_rand();

    ht_register_http_sess(this, sess);
    return sess;
}

void http_session_free(struct http_session *sess)
{
    free(sess);
}

void http_session_destroy(THIS, struct http_session *sess)
{
    struct rtsp_mpegio_streamer *streamer;
    MPEGIO mpegio;

    /* session must be removed from session hast table by now */

    streamer = sess->streamer;
    mpegio = streamer->mpegio;

    log_info("http session %llu closed", sess->session_id);

    mpegio_clientid_destroy(mpegio, sess->mpegio_client_id);

    http_session_free(sess);
}

void http_session_cleanup(struct http_session *sess)
{
    if (sess->fd >= 0){
	ev_io_stop(evloop, &(sess->fd_watcher));
	close(sess->fd);
	sess->fd = -1;
    }
}

static void ev_fd_rx_handler(struct ev_loop *loop, ev_io *w, int revents)
{
    struct http_session *sess = (struct http_session *)w->data;
    THIS = sess->rtsp_server;

    /* Either connection was closed or some data was received.
     * No data is expected anyway, assume a fatal error.
     */

    http_session_delayed_destroy(this, sess->session_id);
}

struct http_session *http_setup_session(THIS, struct in_addr *client_addr, struct url_requested_stream *rs, int fd)
{
    struct http_session *sess;
    struct rtsp_mpegio_streamer *streamer;
    struct mpegio_client *client;
    MPEGIO mpegio;
    int id;

    streamer = mpegio_streamer_prepare(this, client_addr, rs);
    if (streamer == NULL){
	return NULL;
    }
    mpegio = streamer->mpegio;

    sess = http_session_alloc(this);

    sess->fd = fd;

    client = mpegio_client_create(mpegio);
    setnonblocking(fd);
    mpegio_client_setup_fd(client, fd, sess->session_id);

    sess->streamer = streamer;
    mpegio_client_get_parameters(mpegio, client, &sess->mpegio_client_id, NULL, NULL);

    ev_io_init(&sess->fd_watcher, ev_fd_rx_handler, fd, EV_READ);
    sess->fd_watcher.data = sess;
    ev_io_start(evloop, &(sess->fd_watcher));

    log_info("http session %llu, setup mpegio client id: %d", sess->session_id, sess->mpegio_client_id);
    return sess;
}

int http_session_play(THIS, struct http_session *sess)
{
    MPEGIO mpegio;

    mpegio = sess->streamer->mpegio;
    mpegio_clientid_set_status(mpegio, sess->mpegio_client_id, MPEGIO_CLIENT_PLAY);

    return 0;
}
