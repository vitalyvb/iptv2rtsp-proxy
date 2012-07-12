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

#define LOG_MODULE ("rtsp")
#define LOG_PARAM (NULL)

#include "global.h"
#include "mpegio.h"
#include "rtp.h"
#include "utils.h"
#include "rtsp.h"
#include "rtspproto.h"
#include "ht.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

/***********************************************************************/

struct rtsp_mpegio_streamer {
    struct hashable hh;

    struct mpegio_config config;
    MPEGIO mpegio;
    int id;
};

struct rtsp_session {
    struct hashable hh_ssrc;
    struct hashable hh_sess;

    rtsp_session_id session_id;

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
};

struct rtsp_server {
    ebb_server server;

    char server_id[32];
    struct in_addr listen_addr;
    uint16_t listen_port;
    uint16_t rtp_base_port;

    int mpegio_latest_id;
    struct ht streamers_ht;
    int connection_counter;

    ev_io rtcp_input_watcher;
    int rtcp_fd;
    int send_fd;

    ev_timer sess_timeout_watcher;
//    int sess_timeout_last_bkt;

    struct ht sess_id_ht;
    struct ht sess_ssrc_ht;

    struct ht_iterator sess_htiter;

    int mpegio_bufsize;
    int mpegio_delay;
};

#define this (_this)
#define THIS RTSP _this

/***********************************************************************/

struct rtsp_session *rtsp_setup_session(THIS, struct in_addr *client_addr, struct rtsp_transport_descr *transp, struct rtsp_requested_stream *rs);

static struct rtsp_session *rtsp_session_get(THIS, rtsp_session_id *session_id);
static int rtsp_session_play(THIS, struct rtsp_session *sess, struct rtsp_requested_stream *rs);
static int rtsp_session_set_ssrc_hash(THIS, struct rtsp_session *sess, uint32_t ssrc);
static int rtsp_session_all_ssrc_hash_remove(THIS, struct rtsp_session *sess);
static void rtsp_destroy_session(THIS, rtsp_session_id *session_id);

struct rtsp_session *rtsp_session_find_by_ssrc(THIS, uint32_t ssrc);

/***********************************************************************/

#define HEADER_CSEQ		(0)
#define HEADER_SESSION		(1)
#define HEADER_UNSUPPORTED	(2)
#define HEADER_REQUIRE		(3)
#define HEADER_PROXY_REQUIRE	(4)
#define HEADER_USER_AGENT	(5)
#define HEADER_CONTENT_ENCODING	(6)
#define HEADER_CONTENT_TYPE	(7)
#define HEADER_CONTENT_LANGUAGE	(8)
#define HEADER_TRANSPORT	(9)
#define HEADER_PUBLIC		(10)
#define HEADER_RTP_INFO		(11)
#define HEADERS_COUNT		(12)

const struct header_names {
    const char *name;
    int index;
} header_names[] = {
    {"CSeq",			HEADER_CSEQ},
    {"Session",			HEADER_SESSION},
    {"Transport",		HEADER_TRANSPORT},
    {"Require",			HEADER_REQUIRE},
    {"Proxy-Require",		HEADER_PROXY_REQUIRE},
    {"Unsupported",		HEADER_UNSUPPORTED},
    {"User-Agent",		HEADER_USER_AGENT},
    {"Content-Encoding",	HEADER_CONTENT_ENCODING},
    {"Content-Type",		HEADER_CONTENT_TYPE},
    {"Content-Language",	HEADER_CONTENT_LANGUAGE},
    {"Public",			HEADER_PUBLIC},
    {"RTP-Info",		HEADER_RTP_INFO},
    {NULL, -1},
};

/***********************************************************************/

struct req_header {
    int ebbindex;
    char *value;
};

struct server_response {
    struct server_response *next;

    struct client_connection *connection;
    struct client_request *request;

    int abort;
    int status_code;
    const char *reason_phrase;

    struct req_header headers[HEADERS_COUNT];

    char *head;
    int head_length;
    int head_sent;

    char *body;
    int body_length;
    int body_sent;
};

struct client_connection {
    ebb_connection ebb;

    RTSP rtsp_server;
    struct sockaddr_in client_addr;
    char client_addr_str[64];
    int connection_id;

    struct server_response *response_list;
    struct server_response *response_tail;
};


struct client_request {
    ebb_request ebb;

    RTSP rtsp_server;
    struct client_connection *connection;

    int method;
    char *uri;

    struct req_header headers[HEADERS_COUNT];
    int ignore_header_index;		/* ignore value when parsing unknown header */

    char *request_body;
    char *response;
};

#define EBB(_x_) (&((_x_)->ebb))

/************************************************************************/

ebb_connection* new_connection(ebb_server *server, struct sockaddr_in *addr);
void on_close(ebb_connection *connection);
int on_timeout(ebb_connection *connection);

/************************************************************************/

struct server_response *server_response_alloc(struct client_request *request)
{
    struct server_response *resp = xmalloc(sizeof(struct server_response));
    memset(resp, 0, sizeof(struct server_response));

    resp->request = request;
    resp->connection = request->connection;

    return resp;
}

void server_response_free(struct server_response *resp)
{
    int i;

    for (i=0;i<HEADERS_COUNT;i++)
	if (resp->headers[i].value){
	    free(resp->headers[i].value);
	    resp->headers[i].value = NULL;
	}

    free(resp->head);
    free(resp->body);

    free(resp);
}

int server_response_tosend(struct server_response *resp)
{
    assert(resp->next == NULL); /* single responses only */

    if (resp->connection->response_list){
	assert(resp->connection->response_tail);
	resp->connection->response_tail->next = resp;
    } else {
	resp->connection->response_list = resp;
    }

    resp->connection->response_tail = resp;

    return 0;
}

int server_response_cook(struct server_response *resp)
{
    char *buf, *bufpos;
    char *val;
    int buflen = 4096;
    int buffree = buflen;
    int i;

    buf = xmalloc(buflen);
    bufpos = buf;

#define CRLF "\r\n"
#define oprintf(x ...) do { \
	int _l = snprintf(bufpos, buffree, x); \
	buffree -= _l; \
	if (buffree <= 0) { log_error("out of buffer space when cooking response"); free(buf); return -1; } \
	bufpos += _l; \
    } while (0)
    oprintf("RTSP/1.0 %d %s" CRLF, resp->status_code, resp->reason_phrase);
    oprintf("Server: " PROGRAM_NAME " " VERSION CRLF);

    for (i=0;;i++) {
	if (header_names[i].name == NULL)
	    break;

	val = resp->headers[header_names[i].index].value;
	if (val){
	    oprintf("%s: %s" CRLF, header_names[i].name, val);
	}
    }

    if (resp->body_length > 0)
	oprintf("Content-Length: %d" CRLF, resp->body_length);

    oprintf(CRLF);

    resp->head = buf;
    resp->head_length = bufpos-buf;

#undef oprintf
#undef CRLF

    return 0;
}

/************************************************************************/

void client_request_free(struct client_request *request)
{
    int i;

    free(request->uri);

    for (i=0;i<HEADERS_COUNT;i++)
	if (request->headers[i].value){
	    free(request->headers[i].value);
	    request->headers[i].value = NULL;
	}

    free(request->request_body);
    free(request->response);

    free(request);
}

/************************************************************************/

static void process_responses(ebb_connection *_connection)
{
    struct client_connection *connection = (struct client_connection*)_connection;
    struct server_response *response;
    int res;

    assert(connection->response_list);

    response = connection->response_list;

    if (response->head_sent && (response->body_length > 0 && !response->body_sent)){
	/* headers sent, send body */
	response->body_sent = 1;
	res = ebb_connection_write(EBB(connection), response->body, response->body_length, process_responses);
	assert(res);
	return;
    } else if (response->head_sent && (response->body_length == 0 || response->body_sent)){
	/* done, release this response */
	connection->response_list = connection->response_list->next;
	if (connection->response_list == NULL){
	    connection->response_tail = NULL;
	}

	if (response->abort){
	    ebb_connection_schedule_close(EBB(connection));
	    server_response_free(response);
	    return;
	}

	server_response_free(response);
    }

    if (connection->response_list){
	/* send next response */
	response = connection->response_list;

	response->head_sent = 1;
	res = ebb_connection_write(EBB(connection), response->head, response->head_length, process_responses);
	assert(res);
    }
}

#define RTSP_SET_STATUS(_r_, _code_, _descr_) do { (_r_)->status_code = (_code_); (_r_)->reason_phrase = (_descr_); } while (0);
#define STATUS_OK(_r_)			RTSP_SET_STATUS((_r_), 200, "OK")

#define STATUS_BAD_REQ(_r_)		RTSP_SET_STATUS((_r_), 400, "Bad Request")
#define STATUS_NOT_FOUND(_r_)		RTSP_SET_STATUS((_r_), 404, "Not Found")
#define STATUS_INVALID_PARAMETER(_r_)	RTSP_SET_STATUS((_r_), 451, "Invalid Parameter")
#define STATUS_SESS_NOT_FOUND(_r_)	RTSP_SET_STATUS((_r_), 454, "Session Not Found")
#define STATUS_AGGR_NOT_ALLOWED(_r_)	RTSP_SET_STATUS((_r_), 459, "Aggregate Operation Not Allowed")
#define STATUS_ONLY_AGGR_ALLOWED(_r_)	RTSP_SET_STATUS((_r_), 460, "Only aggregate operation allowed")

#define STATUS_INTERNAL_ERROR(_r_)	RTSP_SET_STATUS((_r_), 500, "Internal Server Error")
#define STATUS_NOT_IMPLEMENTED(_r_)	RTSP_SET_STATUS((_r_), 501, "Not Implemented")
#define STATUS_BAD_VERSION(_r_)		RTSP_SET_STATUS((_r_), 505, "RTSP Version Not Supported")

static int rtsp_method_options(struct client_request *request, struct server_response *response, struct rtsp_requested_stream *rs)
{
    struct client_connection *connection = request->connection;
    RTSP rtsp_server = connection->rtsp_server;
    rtsp_session_id sess_id;
    struct rtsp_session *rtsp_sess;

    /* we do not support any options (yet) */
    if (response->headers[HEADER_REQUIRE].value || response->headers[HEADER_PROXY_REQUIRE].value){
	RTSP_SET_STATUS(response, 551, "Option not supported")

	if (request->headers[HEADER_REQUIRE].value)
	    response->headers[HEADER_UNSUPPORTED].value = strdup(request->headers[HEADER_REQUIRE].value);
	else if (request->headers[HEADER_PROXY_REQUIRE].value)
	    response->headers[HEADER_UNSUPPORTED].value = strdup(request->headers[HEADER_PROXY_REQUIRE].value);
    } else {
	STATUS_OK(response);

	//response->headers[HEADER_PUBLIC].value = strdup("OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE");
	response->headers[HEADER_PUBLIC].value = strdup("OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY");

	if (request->headers[HEADER_SESSION].value && 
		parse_rtsp_session_id(request->headers[HEADER_SESSION].value, &sess_id) == 0){
	    rtsp_sess = rtsp_session_get(rtsp_server, &sess_id);
	    if (rtsp_sess){
		rtsp_sess->latest_activity = ev_now(evloop);
		response->headers[HEADER_SESSION].value = strdup(request->headers[HEADER_SESSION].value);
	    }
	}
    }

    return 0;
}

static int rtsp_method_describe(struct client_request *request, struct server_response *response, struct rtsp_requested_stream *rs)
{
    struct client_connection *connection = request->connection;
    char *buf;
    int buflen;
    long long sdp_sess;
    long long sdp_vers;

    sdp_sess = ev_now(evloop)*0x100000000LL;
    sdp_vers = ev_now(evloop);

    buf = NULL;
    buflen = asprintf(&buf, 
	"v=0\r\n"
	"o=- %llu %llu IN IP4 %s\r\n"
	"s=Unnamed\r\n"
	"a=recvonly\r\n"
	"m=video 2000 RTP/AVP 33\r\n"
	"a=rtpmap:33 MP2T/90000\r\n",
	sdp_sess, sdp_vers,
	connection->rtsp_server->server_id);

    if (buflen < 0){
	log_error("asprintf failed");
	return -1;
    }

    STATUS_OK(response);

    response->body = buf;
    response->body_length = buflen;

    response->headers[HEADER_CONTENT_TYPE].value = strdup("application/sdp");

    return 0;
}

static int rtsp_method_setup(struct client_request *request, struct server_response *response, struct rtsp_requested_stream *rs)
{
    struct client_connection *connection = request->connection;
    RTSP rtsp_server = connection->rtsp_server;

    struct rtsp_session *rtsp_sess;
    struct rtsp_transport_descr *transp;

    if (!rs || strcmp(rs->category, "iptv") != 0){
	STATUS_NOT_FOUND(response)
	return 0;
    }

    if (!request->headers[HEADER_TRANSPORT].value){
	STATUS_INVALID_PARAMETER(response);
	return 0;
    }

    if (request->headers[HEADER_SESSION].value){
	STATUS_AGGR_NOT_ALLOWED(response);
	return 0;
    }

    transp = parse_transport_header(request->headers[HEADER_TRANSPORT].value, strlen(request->headers[HEADER_TRANSPORT].value));
    if (transp == NULL){
	STATUS_INVALID_PARAMETER(response);
	return 0;
    }

    if ((strcmp(transp->transport, "RTP/AVP") != 0 &&
		strcmp(transp->transport, "RTP/AVP/UDP") != 0) ||
		transp->multicast){

	RTSP_SET_STATUS(response, 461, "Unsupported Transport");
	free_transport_header(transp);
	return 0;
    }

    transp->multicast = 0;
    transp->unicast = 1;
    transp->destination[0] = 0;

    transp->server_port_lo = rtsp_server->rtp_base_port;
    transp->server_port_hi = rtsp_server->rtp_base_port+1;

    rtsp_sess = rtsp_setup_session(connection->rtsp_server, &connection->client_addr.sin_addr, transp, rs);

    if (rtsp_sess){
	STATUS_OK(response);

	response->headers[HEADER_TRANSPORT].value = cook_transport_header(transp);

	response->headers[HEADER_SESSION].value = xmalloc(32);
	cook_rtsp_session_id(response->headers[HEADER_SESSION].value, 32, &rtsp_sess->session_id);

	log_info("client %s connection id: %d, created new session %llu", connection->client_addr_str, connection->connection_id, rtsp_sess->session_id);
    } else {
	log_warning("failed to setup session");
	STATUS_NOT_FOUND(response);
    }

    free_transport_header(transp);

    return 0;
}

static int rtsp_method_teardown(struct client_request *request, struct server_response *response, struct rtsp_requested_stream *rs)
{
    struct client_connection *connection = request->connection;
    RTSP rtsp_server = connection->rtsp_server;
    rtsp_session_id sess_id = 0;

    if (parse_rtsp_session_id(request->headers[HEADER_SESSION].value, &sess_id)){
	log_warning("invalid session header");
	STATUS_SESS_NOT_FOUND(response);
	return 0;
    }

    STATUS_OK(response);
    rtsp_destroy_session(rtsp_server, &sess_id);

    return 0;
}

static int rtsp_method_play(struct client_request *request, struct server_response *response, struct rtsp_requested_stream *rs)
{
    struct client_connection *connection = request->connection;
    RTSP rtsp_server = connection->rtsp_server;
    rtsp_session_id sess_id = 0;
    struct rtsp_session *rtsp_sess;
    uint32_t rtp_seq;

    if (parse_rtsp_session_id(request->headers[HEADER_SESSION].value, &sess_id)){
	log_warning("invalid session header");
	STATUS_SESS_NOT_FOUND(response);
	return 0;
    }

    rtsp_sess = rtsp_session_get(rtsp_server, &sess_id);
    if (!rtsp_sess){
	log_warning("session %s(%llu) not found", request->headers[HEADER_SESSION].value, sess_id);
	STATUS_SESS_NOT_FOUND(response);
	return 0;
    }

    if (!rtsp_sess->playing){
	rtsp_sess->playing = 1;
	rtsp_session_play(rtsp_server, rtsp_sess, rs);
    }

    STATUS_OK(response);
    response->headers[HEADER_SESSION].value = strdup(request->headers[HEADER_SESSION].value);

    if (mpegio_clientid_get_parameters(rtsp_sess->streamer->mpegio, rtsp_sess->mpegio_client_id, NULL, &rtp_seq) == 0){
	char *buf = xmalloc(64);
	cook_rtsp_rtp_info(buf, 64, rs, rtp_seq);
	response->headers[HEADER_RTP_INFO].value = buf;
    } else {
	log_error("can not get mpegio client %d parameters", rtsp_sess->mpegio_client_id);
    }

    return 0;
}

static int rtsp_method_pause(struct client_request *request, struct server_response *response, struct rtsp_requested_stream *rs)
{
    STATUS_NOT_IMPLEMENTED(response);
    return 0;
}

static void request_complete(ebb_request *_request)
{
    struct client_request *request = (struct client_request*)_request;
    struct client_connection *connection = request->connection;
    struct server_response *response;
    int i;

    if (debug){
	char *val;

	log_info("=== Request received ===");
	log_info("    Protocol:           %s/%d.%d", (request->ebb.protocol == EBB_PROTOCOL_HTTP) ? "HTTP" :
					    (request->ebb.protocol == EBB_PROTOCOL_RTSP) ? "RTSP" : "????",
					    request->ebb.version_major, request->ebb.version_minor);
	log_info("    URI:                %s", request->uri);
	log_info("    Method:             %s", (request->ebb.method == EBB_OPTIONS) ? "OPTIONS" :
					    (request->ebb.method == EBB_DESCRIBE) ? "DESCRIBE" :
					    (request->ebb.method == EBB_ANNOUNCE) ? "ANNOUNCE" :
					    (request->ebb.method == EBB_PAUSE) ? "PAUSE" :
					    (request->ebb.method == EBB_PLAY) ? "PLAY" :
					    (request->ebb.method == EBB_RECORD) ? "RECORD" :
					    (request->ebb.method == EBB_REDIRECT) ? "REDIRECT" :
					    (request->ebb.method == EBB_SETUP) ? "SETUP" :
					    (request->ebb.method == EBB_TEARDOWN) ? "TEARDOWN" :
					    (request->ebb.method == EBB_GET_PARAMETER) ? "GET_PARAMETER" :
					    (request->ebb.method == EBB_SET_PARAMETER) ? "SET_PARAMETER" : "????");
	log_info("    Content-Length:     %d", request->ebb.content_length);
	log_info("    Transfer-Encoding:  %s", (request->ebb.transfer_encoding == EBB_IDENTITY) ? "IDENTITY" :
					    (request->ebb.transfer_encoding == EBB_CHUNKED) ? "CHUNKED" : "????");

	for (i=0;;i++) {
	    if (header_names[i].name == NULL)
		break;

	    val = request->headers[header_names[i].index].value;
	    if (val){
		log_info("    Header:             %s: %s", header_names[i].name, val);
	    }
	}
    }

    response = server_response_alloc(request);

    if (request->ebb.protocol != EBB_PROTOCOL_RTSP ||
		!request->uri ||
		request->ebb.transfer_encoding == EBB_CHUNKED ||
		!request->headers[HEADER_CSEQ].value){
	STATUS_BAD_REQ(response);
	response->abort = 1;
    } else if (request->ebb.version_major != 1 || request->ebb.version_minor != 0) {
	STATUS_BAD_VERSION(response);
	response->abort = 1;
    } else if (request->ebb.method != EBB_OPTIONS &&
		request->ebb.method != EBB_PLAY &&
		request->ebb.method != EBB_PAUSE &&
		request->ebb.method != EBB_SETUP &&
		request->ebb.method != EBB_DESCRIBE &&
		request->ebb.method != EBB_TEARDOWN) {
	STATUS_NOT_IMPLEMENTED(response);
    } else if ((request->ebb.method == EBB_PLAY ||
		request->ebb.method == EBB_PAUSE ||
		request->ebb.method == EBB_TEARDOWN) &&
		!request->headers[HEADER_SESSION].value){
	STATUS_SESS_NOT_FOUND(response);
    } else {
	int res = -1;
	struct rtsp_requested_stream *rs = parse_requested_stream(request->uri, strlen(request->uri));


	if (request->headers[HEADER_CSEQ].value)
	    response->headers[HEADER_CSEQ].value = strdup(request->headers[HEADER_CSEQ].value);

	if (request->ebb.method == EBB_OPTIONS) {
	    res = rtsp_method_options(request, response, rs);
	} else if (request->ebb.method == EBB_DESCRIBE) {
	    res = rtsp_method_describe(request, response, rs);
	} else if (request->ebb.method == EBB_SETUP) {
	    res = rtsp_method_setup(request, response, rs);
	} else if (request->ebb.method == EBB_TEARDOWN) {
	    res = rtsp_method_teardown(request, response, rs);
	} else if (request->ebb.method == EBB_PLAY) {
	    res = rtsp_method_play(request, response, rs);
	} else if (request->ebb.method == EBB_PAUSE) {
	    res = rtsp_method_pause(request, response, rs);
	}

	free_requested_stream(rs);

	if (res < 0){
	    // XXX clear headers ?
	    STATUS_INTERNAL_ERROR(response);
	}

    }

    if (server_response_cook(response)){
	log_error("server_response_cook failed");
    } else {
	server_response_tosend(response);

	process_responses(EBB(connection));
    }

    client_request_free(request);
}

static void element_uri(ebb_request *_request, const char *at, size_t length)
{
    struct client_request *request = (struct client_request*)_request;

    char *buf;

    buf = xmalloc(length+1);
    memcpy(buf, at, length);
    buf[length] = 0;

    request->uri = buf;
}

static void element_body(ebb_request *_request, const char *at, size_t length)
{
    struct client_request *request = (struct client_request*)_request;

    char *buf;

    buf = xmalloc(length+1);
    memcpy(buf, at, length);
    buf[length] = 0;

    request->request_body = buf;
}

static void header_field(ebb_request *_request, const char *at, size_t length, int header_index)
{
    struct client_request *request = (struct client_request*)_request;
    int i;
    int header_idx;

    request->ignore_header_index = header_index;

    for (i=0;;i++) {
	if (header_names[i].name == NULL)
	    break;

	if (strncmp(header_names[i].name, at, length) == 0){
	    header_idx = header_names[i].index;
	    request->headers[header_idx].ebbindex = header_index;
	    request->ignore_header_index = -1;
	    break;
	}
    }
}

static void header_value(ebb_request *_request, const char *at, size_t length, int header_index)
{
    struct client_request *request = (struct client_request*)_request;
    char *buf;
    int i;

    if (request->ignore_header_index == header_index)
	return;

    for (i=0;i<HEADERS_COUNT;i++){
	if (request->headers[i].ebbindex == header_index){

	    buf = xmalloc(length+1);
	    memcpy(buf, at, length);
	    buf[length] = 0;

	    request->headers[i].value = buf;

	    break;
	}
    }
}

static void headers_done_cb(ebb_request *request)
{
    //log_info("headers done");
}

static ebb_request* new_request(ebb_connection *_connection)
{
    struct client_connection *connection = (struct client_connection*)_connection;
    struct client_request *request;
    int i;

    request = xmalloc(sizeof(struct client_request));
    if (request == NULL){
	return NULL;
    }

    memset(request, 0, sizeof(struct client_request));

    request->rtsp_server = connection->rtsp_server;
    request->connection = connection;
    request->ignore_header_index = -1;

    for (i=0;i<HEADERS_COUNT;i++)
	request->headers[i].ebbindex = -1;

    ebb_request_init(EBB(request));

    EBB(request)->on_complete = request_complete;
    EBB(request)->on_uri = element_uri;
    EBB(request)->on_header_field = header_field;
    EBB(request)->on_header_value = header_value;
    EBB(request)->on_headers_complete = headers_done_cb;
    EBB(request)->on_body = element_body;


    //log_info("new request");
    return EBB(request);
}

ebb_connection* new_connection(ebb_server *server, struct sockaddr_in *addr)
{
    struct client_connection *connection;

    /* XXX connections are not freed on server shutdown */
    connection = xmalloc(sizeof(struct client_connection));
    if (connection == NULL) {
	return NULL;
    }

    memset(connection, 0, sizeof(struct client_connection));

    connection->rtsp_server = (RTSP) server->data;
    connection->connection_id = connection->rtsp_server->connection_counter++;
    memcpy(&connection->client_addr, addr, sizeof(struct sockaddr_in));

    ebb_connection_init(EBB(connection));

    EBB(connection)->new_request = new_request;
    EBB(connection)->on_close = on_close;
    EBB(connection)->on_timeout = on_timeout;

    inet_ntop(AF_INET, &addr->sin_addr, connection->client_addr_str,
					sizeof(connection->client_addr_str));
    log_info("client %s connected, id %d", connection->client_addr_str, connection->connection_id);

    return EBB(connection);
}

void on_close(ebb_connection *_connection)
{
    struct client_connection *connection = (struct client_connection*)_connection;
    log_info("connection id %d closed", connection->connection_id);

    // XXX todo
    // FIXME there can be requests or something in progress referencing connection
    free(connection);
}

int on_timeout(ebb_connection *connection)
{
    // never timeout
    return EBB_AGAIN;
}

/************************************************************************/

static hthash_value htfunc_session(const void *item)
{
    const struct rtsp_session *sess = item;
    /* XXX maybe it's a good idea to slightly randomize this,
     * like xor value with time daemon started or something
     */
    return sess->session_id ^ (sess->session_id >> 32);
}

static int htfunc_session_cmp(const void *_item1, const void *_item2_or_key)
{
    const struct rtsp_session *item1 = _item1;
    const struct rtsp_session *item2_or_key = _item2_or_key;
    /* we can't use subtract here because of integer size difference */
    if (likely(item1->session_id == item2_or_key->session_id))
	return 0;
    if (item1->session_id < item2_or_key->session_id)
	return -1;
    return 1;
}

static struct rtsp_session *rtsp_session_alloc(THIS)
{
    struct rtsp_session *sess;

    sess = xmalloc(sizeof(struct rtsp_session));
    memset(sess, 0 , sizeof(struct rtsp_session));

    sess->session_id = my_rand();

    ht_insert(&this->sess_id_ht, sess, htfunc_session);
    return sess;
}

void rtsp_session_free(struct rtsp_session *sess)
{
    free(sess);
}

static struct rtsp_session *rtsp_session_get(THIS, rtsp_session_id *session_id)
{
    struct rtsp_session tmpsess;
    struct rtsp_session *sess;

    tmpsess.session_id = *session_id;

    sess = ht_find(&this->sess_id_ht, &tmpsess, htfunc_session, htfunc_session_cmp);
    return sess;
}

static struct rtsp_session *rtsp_session_remove(THIS, rtsp_session_id *session_id)
{
    struct rtsp_session tmpsess;
    struct rtsp_session *sess;

    tmpsess.session_id = *session_id;

    sess = ht_remove(&this->sess_id_ht, &tmpsess, htfunc_session, htfunc_session_cmp);
    return sess;
}

/************************************************************************/

static hthash_value htfunc_streamer(const void *item)
{
    const struct rtsp_mpegio_streamer *streamer = item;
    return hashword((void*)&streamer->config, MPEGIO_KEY_SIZE/sizeof(uint32_t), HASH_INITIAL);
}

static int htfunc_streamer_cmp(const void *_item1, const void *_item2_or_key)
{
    const struct rtsp_mpegio_streamer *item1 = _item1;
    const struct rtsp_mpegio_streamer *item2_or_key = _item2_or_key;

    return memcmp(&item1->config, &item2_or_key->config, MPEGIO_KEY_SIZE);
}


static MPEGIO create_setup_mpegio(struct mpegio_config *conf)
{
    MPEGIO mpegio;

    mpegio = mpegio_alloc();
    if (mpegio == NULL)
	return NULL;

    if (mpegio_configure(mpegio, conf)){
        mpegio_free(mpegio);
        return NULL;
    }
    if (mpegio_init(mpegio)){
        mpegio_free(mpegio);
        return NULL;
    }

    return mpegio;
}

void mpegio_send_error_handler(void *param, uint32_t ssrc, int in_errno)
{
    THIS = param;
    struct rtsp_session *sess;
    ev_tstamp now;

    sess = rtsp_session_find_by_ssrc(this, ssrc);

    if (sess != NULL){
	now = ev_now(evloop);

	if (now - sess->last_error_tstamp > 2.0){
	    sess->send_errors = 1;
	    sess->last_error_tstamp = now;
	} else if (now - sess->last_error_tstamp > 0.5){
	    sess->send_errors++;
	    sess->last_error_tstamp = now;
	}

	if (sess->send_errors > 5){
	    log_warning("deactivating session %llu, too many consequent send errors", sess->session_id);
	    mpegio_clientid_set_active(sess->streamer->mpegio, sess->mpegio_client_id, 0);
	    sess->playing = 0;
	}
    }
}

int requested_stream_to_mpegio_key(THIS, struct rtsp_requested_stream *rs, struct mpegio_config *conf)
{
    char *p = NULL;

    memset(conf, 0, sizeof(struct mpegio_config));

    conf->port = strtol(rs->port, &p, 10);
    if (p && p[0] != 0){
	log_error("invalid port number: %s", rs->port);
	return -1;
    } else if (conf->port < 1024 || conf->port > 65534){
	log_error("port number %d out of valid range (1024...65534)", conf->port);
	return -1;
    }

    if (inet_pton(AF_INET, rs->group, &conf->addr) != 1){
	log_error("invalid ip address: %s", rs->group);
	return -1;
    }

    return 0;
}

struct rtsp_session *rtsp_setup_session(THIS, struct in_addr *client_addr, struct rtsp_transport_descr *transp, struct rtsp_requested_stream *rs)
{
    struct rtsp_session *sess;
    struct rtsp_mpegio_streamer *streamer;
    struct mpegio_client *client;
    struct rtsp_mpegio_streamer streamer_conf;
    MPEGIO mpegio;

    uint32_t rtp_seq;
    uint32_t ssrc;

    if (requested_stream_to_mpegio_key(this, rs, &streamer_conf.config)){
	return NULL;
    }

    streamer = ht_find(&this->streamers_ht, &streamer_conf, htfunc_streamer, htfunc_streamer_cmp);

    if (streamer == NULL) {
	streamer = xmalloc(sizeof(struct rtsp_mpegio_streamer));
	memset(streamer, 0, sizeof(struct rtsp_mpegio_streamer));

	streamer->id = this->mpegio_latest_id++;
	memcpy(&streamer->config, &streamer_conf.config, MPEGIO_KEY_SIZE);

	streamer->config.send_fd = this->send_fd;
	streamer->config.init_buf_size = this->mpegio_bufsize;
	streamer->config.streaming_delay = this->mpegio_delay;
	streamer->config.on_send_error = mpegio_send_error_handler;
	streamer->config.cbdata = this;

	mpegio = create_setup_mpegio(&streamer->config);
	if (mpegio == NULL){
	    xfree(streamer);
	    log_info("mpegio setup failed");
	    return NULL;
	}

	streamer->mpegio = mpegio;

	ht_insert(&this->streamers_ht, streamer, htfunc_streamer);
    } else {
	if (!mpegio_is_initialized(streamer->mpegio) && mpegio_init(streamer->mpegio)){
	    log_error("mpegio reinit failed");
	    return NULL;
	}
	mpegio = streamer->mpegio;
    }

    sess = rtsp_session_alloc(this);

    memcpy(&sess->addr, client_addr, sizeof(struct in_addr));
    sess->client_port_lo = transp->client_port_lo;
    sess->client_port_hi = transp->client_port_hi;
    sess->latest_activity = ev_now(evloop);

    sess->streamer = streamer;

    // XXX handle ssrc collisions
    while ((ssrc = my_rand()) == 0);

    client = mpegio_client_create(mpegio, &sess->addr, sess->client_port_lo, ssrc);

    transp->ssrc = ssrc;

    mpegio_client_get_parameters(mpegio, client, &sess->mpegio_client_id, NULL, &rtp_seq);

    if (rtsp_session_set_ssrc_hash(this, sess, ssrc) < 0){
	log_error("session setup fail");
	return NULL;
    }

    log_info("session %llu, setup mpegio client id: %d ssrc: %08x seq: %d", sess->session_id, sess->mpegio_client_id, ssrc, rtp_seq);
    return sess;
}

void rtsp_free_session(THIS, struct rtsp_session *sess)
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

void rtsp_destroy_session(THIS, rtsp_session_id *session_id)
{
    struct rtsp_session *sess = rtsp_session_remove(this, session_id);

    if (sess){
	rtsp_free_session(this, sess);
    } else {
	log_warning("session to destroy is not found");
    }
}

static hthash_value htfunc_sess_ssrc(const void *item)
{
    const struct rtsp_session *sess = item;
    /* XXX see htfunc_session() */
    return sess->ssrc;
}

int rtsp_session_all_ssrc_hash_remove(THIS, struct rtsp_session *sess)
{
    struct rtsp_session *removed;

    removed = ht_remove(&this->sess_ssrc_ht, sess, htfunc_sess_ssrc, NULL);

    if (removed != NULL && removed != sess){
	log_warning("oops, just have removed wrong session because of ssrc collision!");
    }

    return removed == NULL ? -1 : 0;
}

struct rtsp_session *rtsp_session_find_by_ssrc(THIS, uint32_t ssrc)
{
    struct rtsp_session tmpsess;
    struct rtsp_session *sess;

    tmpsess.ssrc = ssrc;

    sess = ht_find(&this->sess_ssrc_ht, &tmpsess, htfunc_sess_ssrc, NULL);
    return sess;
}

int rtsp_session_set_ssrc_hash(THIS, struct rtsp_session *sess, uint32_t ssrc)
{
    sess->ssrc = ssrc;
    ht_insert(&this->sess_ssrc_ht, sess, htfunc_sess_ssrc);

    return 0;
}

int rtsp_session_play(THIS, struct rtsp_session *sess, struct rtsp_requested_stream *rs)
{
    struct rtsp_mpegio_streamer *streamer;
    MPEGIO mpegio;
    struct mpegio_config conf;


    if (requested_stream_to_mpegio_key(this, rs, &conf)){
	return -1;
    }

    streamer = sess->streamer;

    /* xxx compare streamer conf and rs conf */

    mpegio = streamer->mpegio;

    mpegio_clientid_set_active(mpegio, sess->mpegio_client_id, 1);

    return 0;
}

/************************************************************************/

static void ev_rtcp_input_handler(struct ev_loop *loop, ev_io *w, int revents)
{
    char buf[2048];
    struct rtsp_session *sess;
    THIS = (RTSP) w->data;
    struct rtcp_header *header;
    struct rtcp_receiver_report *rr;
    char *start;
    int len;
    int report_len, repn;

    len = recv(this->rtcp_fd, buf, 2048, MSG_DONTWAIT);

    if (len <= 0) {
	return;
    } else if (len < (int)sizeof(struct rtcp_header)) {
	// this can be a valid packet(?) but we're not interested
	return;
    }

    start = buf;

    do {
	header = (struct rtcp_header*)start;

	if (header->version != 2){
	    log_warning("invalid rtcp packet: bad version");
	    break;
	}

	report_len = (int)ntohs(header->length4)*4 + 4;
	if (report_len < 8){
	    log_warning("invalid rtcp packet: short packet");
	    break;
	}

	log_debug("RTCP: v:%d p:%d c:%d t:%d l:%d(b) s:%08x",
		header->version,
		header->padding,
		header->reports_count,
		header->packet_type,
		report_len,
		ntohl(header->sender_ssrc));

	if (len < report_len){
	    log_warning("invalid rtcp packet: short packet");
	    break;
	}

	if (header->packet_type == RTCP_TYPE_SENDER_REPORT){
	    // ignore
	} else if (header->packet_type == RTCP_TYPE_RECEIVER_REPORT){

	    if (report_len < (int)(sizeof(struct rtcp_header) + sizeof(struct rtcp_receiver_report)*header->reports_count)){
		log_warning("invalid rtcp packet: short packet");
		break;
	    }

	    rr = (struct rtcp_receiver_report*)(start+sizeof(struct rtcp_header));

	    for (repn=header->reports_count; repn>0; repn--) {
		log_debug("\tRTCP RR %08x %d/256 loss:%d  xseq:%x j:%d sr:%d @%d",
			    ntohl(rr->ssrc),
			    rr->fraction_lost,
			    RTCP_RR_CUMULATIVE_LOST(rr),
			    ntohl(rr->extended_highest_seq),
			    ntohl(rr->interarrival_jitter),
			    ntohl(rr->last_sr),
			    ntohl(rr->delay_since_last_sr));

		sess = rtsp_session_find_by_ssrc(this, ntohl(rr->ssrc));
		if (sess == NULL){
		    log_debug("got rr for unknown ssrc %08x", ntohl(rr->ssrc));
		} else {
		    int jitter = ntohl(rr->interarrival_jitter);
		    sess->latest_activity = ev_now(evloop);
		    sess->rtcp_reported_packet_loss = RTCP_RR_CUMULATIVE_LOST(rr);

		    if (rr->fraction_lost || jitter >= WARN_JITTER_VALUE_RTCP_RR){
			log_info("rtcp report: session %llu, loss rate since last report: %d/256, %d total, interarrival jitter: %d",
				sess->session_id, rr->fraction_lost, sess->rtcp_reported_packet_loss, jitter);
		    }

		}

		rr++;
	    }

	} else if (header->packet_type == RTCP_TYPE_SOURCE_REPORT){
	    // ignore
	} else if (header->packet_type == RTCP_TYPE_BYE){
	    // ignore, nobody sends it anyways
	} else
	    break;

	start += report_len;
	len -= report_len;
    } while (len > 0);
}

int rtcp_setup(THIS)
{
    struct sockaddr_in addr;
    int res;
    int fd;

    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
	log_error("can not create rtcp recv socket");
	return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(this->rtp_base_port+1);
    addr.sin_addr.s_addr = this->listen_addr.s_addr;

    res = bind(fd, (struct sockaddr*)&addr, sizeof(addr));

    if (res < 0){
	log_error("can not bind to rtcp socket");
	close(fd);
	return -1;
    }

    this->rtcp_fd = fd;

    ev_io_init(&this->rtcp_input_watcher, ev_rtcp_input_handler, this->rtcp_fd, EV_READ);
    this->rtcp_input_watcher.data = this;
    ev_io_start(evloop, &(this->rtcp_input_watcher));

    return 0;
}

void rtcp_destroy(THIS)
{
    ev_io_stop(evloop, &(this->rtcp_input_watcher));
    close(this->rtcp_fd);
    this->rtcp_fd = -1;
}

/************************************************************************/

static void ev_sess_check_timeout_handler(struct ev_loop *loop, ev_timer *w, int revents)
{
    /* Here we check for timeouted sessions and destroy them.
     * Only part of the table is checked per call to reduce time the event loop is
     * being 'blocked'.
     */
    const int bucket_per_iteration = (RTSP_SESS_HASHSIZE)/(RTSP_CHECK_SESSIONS_ROUND/RTSP_CHECK_SESSION_TIMEOUTS_ITER) + 1;
    THIS = (RTSP) w->data;
    void *iterstate = NULL;
    struct rtsp_session *item;
    int buckets_limit = bucket_per_iteration;

    ev_tstamp timeouted = ev_now(evloop) - NO_RTCP_SESSION_TIMEOUT;

    while ((item = ht_iterate(&this->sess_htiter, &iterstate, &buckets_limit)) != NULL){
	if (item->latest_activity < timeouted){

	    ht_remove(&this->sess_id_ht, item, htfunc_session, htfunc_session_cmp);
	    rtsp_free_session(this, item);

	}
	if (ht_iterator_is_bucket_end(&this->sess_htiter, &iterstate) && buckets_limit <= 0){
	    break;
	}
    }

}

/************************************************************************/

RTSP rtsp_alloc()
{
    struct rtsp_server *_this;

    _this = xmalloc(sizeof(struct rtsp_server));

    memset(_this, 0, sizeof(struct rtsp_server));

    this->rtcp_fd = -1;
    this->send_fd = -1;

    return _this;
}

int rtsp_load_config(THIS, dictionary * d)
{
    const char *ini_listen_host;
    uint16_t ini_listen_port, ini_rtp_server_base_port;
    int ini_mpegio_bufsize, ini_mpegio_delay;

    ini_listen_host = iniparser_getstring(d, "rtsp:listen_host", "0.0.0.0");

    if (server_listen_port)
	ini_listen_port = server_listen_port;
    else
	ini_listen_port = iniparser_getint(d, "rtsp:listen_port", 554);

    ini_rtp_server_base_port = iniparser_getint(d, "rtsp:rtp_server_base_port", 4000);

    ini_mpegio_bufsize = iniparser_getint(d, "mpegio:buffer_size", MPEGIO_DEFAULT_RINGBUF_SIZE);
    ini_mpegio_delay = iniparser_getint(d, "mpegio:delay", MPEGIO_MAX_STREAM_DELAY);

    strncpy(this->server_id, server_str_id, sizeof(this->server_id)-1);
    this->server_id[sizeof(this->server_id)-1] = 0;

    this->listen_port = ini_listen_port;

    if (strcmp(ini_listen_host, "0.0.0.0")) {
	if (inet_aton(ini_listen_host, &this->listen_addr) == 0){
	    log_error("mpegio: can not parse listen address");
	    return -1;
	}
    } else {
	this->listen_addr.s_addr = htonl (INADDR_ANY);
    }

    this->rtp_base_port = ini_rtp_server_base_port;

    this->mpegio_bufsize = ini_mpegio_bufsize;
    this->mpegio_delay = ini_mpegio_delay;

    return 0;
}

int rtsp_init(THIS)
{
    struct sockaddr_in addr;
    int fd, tmp, res;

    ht_init(&this->sess_id_ht, RTSP_SESS_HASHSIZE, offsetof(struct rtsp_session, hh_sess));
    ht_init(&this->sess_ssrc_ht, RTSP_SESS_HASHSIZE, offsetof(struct rtsp_session, hh_ssrc));
    ht_init(&this->streamers_ht, RTSP_MPEGIO_HASHSIZE, offsetof(struct rtsp_mpegio_streamer, hh));

    ht_iterator_init(&this->sess_htiter, &this->sess_id_ht);

    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
	log_error("can not create send socket");
	return -1;
    }

    tmp = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &tmp, sizeof(tmp))){
	log_warning("setting IP_RECVERR failed, error detection is reduced");
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(this->rtp_base_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    res = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (res < 0){
	log_error("can not bind rtp base socket");
	close(fd);
	return -1;
    }

    this->send_fd = fd;

    ebb_server_init(&this->server, evloop);

    if (rtcp_setup(this)){
	close(this->send_fd);
	this->send_fd = -1;
	return -1;
    }

    this->server.new_connection = new_connection;
    this->server.data = this;

    if (ebb_server_listen_on_port(&this->server, this->listen_port) < 0){
	log_error("Failed to start RTSP server on port %d", this->listen_port);
	return -1;
    }

    ev_timer_init(&this->sess_timeout_watcher, ev_sess_check_timeout_handler,
		    RTSP_CHECK_SESSION_TIMEOUTS_ITER, RTSP_CHECK_SESSION_TIMEOUTS_ITER);
    this->sess_timeout_watcher.data = this;

    ev_timer_start(evloop, &this->sess_timeout_watcher);

    return 0;
}

int ht_free_session(void *item, void *param)
{
    THIS = param;
    struct rtsp_session *sess = item;

    rtsp_destroy_session(this, &sess->session_id);

    return HT_CB_CONTINUE;
}

int ht_free_streamer(void *item, void *param)
{
    struct rtsp_mpegio_streamer *streamer = item;

    mpegio_free(streamer->mpegio);
    xfree(streamer);

    return HT_CB_CONTINUE;
}

void rtsp_cleanup(THIS)
{
    ebb_server_unlisten(&this->server);
    ev_timer_stop(evloop, &(this->sess_timeout_watcher));

    rtcp_destroy(this);

    ht_remove_all(&this->sess_ssrc_ht, NULL, NULL);
    ht_remove_all(&this->sess_id_ht, ht_free_session, this);
    ht_remove_all(&this->streamers_ht, ht_free_streamer, this);

    ht_destroy(&this->streamers_ht);
    ht_destroy(&this->sess_ssrc_ht);
    ht_destroy(&this->sess_id_ht);

    xfree(this);
}
