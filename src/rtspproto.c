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

#define LOG_MODULE ("rtspproto")
#define LOG_PARAM (NULL)

#include "global.h"
#include "rtp.h"
#include "utils.h"
#include "rtspproto.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

/**********************************************************************************/

int cook_rtsp_session_id(char *dstbuf, int bufsize, rtsp_session_id *sess_id)
{
    assert(sizeof(long long unsigned int) == sizeof(rtsp_session_id));
    return snprintf(dstbuf, bufsize, "%llu", (long long unsigned int)*sess_id);
}

int parse_rtsp_session_id(char *buf, rtsp_session_id *sess_id)
{
    char *ebuf;
    long long ts;

    if (!buf || *buf == 0)
	return -1;

    ts = strtoull(buf, &ebuf, 10);

    if (*ebuf != 0)
	return -1;

    *sess_id = ts;

    return 0;
}

/**********************************************************************************/

static int parse_port_range(char *str, int *from, int *to)
{
    char *endp1, *endp2;
    int i1, i2;

    i1 = strtoul(str, &endp1, 10);
    if (*endp1 == 0){
	*from = i1;
	*to = i1;
	return 0;
    }

    if (*endp1 == '-'){
	endp1++;

	i2 = strtoul(endp1, &endp2, 10);
	if (*endp2 == 0){
	    *from = i1;
	    *to = i2;
	    return 0;
	}
    }

    return -1;
}

/**********************************************************************************/

char *cook_transport_header(const struct rtsp_transport_descr *transp)
{
    int buffree = 256;
    char *buf, *bufpos;

    buf = xmalloc(buffree);
    bufpos = buf;

#define oprintf(x ...) do { \
	int _l = snprintf(bufpos, buffree, x); \
	buffree -= _l; \
	if (buffree <= 0) { log_error("out of buffer space when cooking response"); free(buf); return NULL; } \
	bufpos += _l; \
    } while (0)
    oprintf("%s", transp->transport);

    if (transp->unicast)
	oprintf(";unicast");
    else if (transp->multicast)
	oprintf(";multicast");

    if (transp->client_port_lo > 0){
	if (transp->client_port_lo >= transp->client_port_hi)
	    oprintf(";client_port=%u", transp->client_port_lo);
	else
	    oprintf(";client_port=%u-%u", transp->client_port_lo, transp->client_port_hi);
    }

    if (transp->server_port_lo > 0){
	if (transp->server_port_lo >= transp->server_port_hi)
	    oprintf(";server_port=%u", transp->server_port_lo);
	else
	    oprintf(";server_port=%u-%u", transp->server_port_lo, transp->server_port_hi);
    }

    if (transp->destination[0])
	oprintf(";destination=%s", transp->destination);

    if (transp->ssrc)
	oprintf(";ssrc=%08x", transp->ssrc);

#undef oprintf

    return buf;
}


struct rtsp_transport_descr *alloc_transport_header()
{
    struct rtsp_transport_descr *transp;
    transp  = xmalloc(sizeof(struct rtsp_transport_descr));
    memset(transp, 0, sizeof(struct rtsp_transport_descr));
    return transp;
}

void free_transport_header(struct rtsp_transport_descr *t)
{
    free(t);
}

struct rtsp_transport_descr *parse_transport_header(char *in_text, int len)
{
    char *buf, *tokstr, *token, *tokptr = NULL;
    struct rtsp_transport_descr *transp = alloc_transport_header();
    int toknum;

    buf = xmalloc(len+1);
    memcpy(buf, in_text, len);
    buf[len] = 0;

    tokstr = buf;
    for (toknum=0;toknum<32;toknum++) {
	token = strtok_r(tokstr, ";", &tokptr);
	tokstr = NULL;
	if (token == NULL)
	    break;

	if (toknum == 0){
	    strncpy(transp->transport, token, sizeof(transp->transport)-1);
	} else {
	    char *key = token;
	    char *value = strchr(token, '=');

	    if (value != NULL){
		value[0] = 0;
		value++;
	    }

	    if (strcmp(key, "unicast") == 0){
		transp->unicast = 1;
	    } else if (strcmp(key, "multicast") == 0){
		transp->multicast = 1;
	    } else if (strcmp(key, "destination") == 0 && value){
		strncpy(transp->destination, value, sizeof(transp->destination)-1);
	    } else if (strcmp(key, "client_port") == 0 && value){
		parse_port_range(value, &transp->client_port_lo, &transp->client_port_hi);
	    } else if (strcmp(key, "server_port") == 0 && value){
		parse_port_range(value, &transp->server_port_lo, &transp->server_port_hi);
	    }
	    /* do not parse ssrc field */
	}

    }

    log_debug("== Parsed Transport header");
    log_debug("    %s", transp->transport);
    log_debug("    unicast: %d, multicast: %d", transp->unicast, transp->multicast);
    log_debug("    dest: %s", transp->destination);
    log_debug("    client ports: %d-%d", transp->client_port_lo, transp->client_port_hi);
    log_debug("    server ports: %d-%d", transp->server_port_lo, transp->server_port_hi);

    free(buf);

    return transp;
}

/**********************************************************************************/

static struct rtsp_requested_stream *alloc_requested_stream()
{
    struct rtsp_requested_stream *rs;
    rs  = xmalloc(sizeof(struct rtsp_requested_stream));
    memset(rs, 0, sizeof(struct rtsp_requested_stream));
    return rs;
}

void free_requested_stream(struct rtsp_requested_stream *s)
{
    free(s);
}

struct rtsp_requested_stream *parse_requested_stream(char *in_text, int len)
{
    char *buf, *p, *tokstr, *token, *tokptr = NULL;
    struct rtsp_requested_stream *rs = alloc_requested_stream();
    char *hostname_start, *path_start;
    int toknum;

    buf = xmalloc(len+1);
    memcpy(buf, in_text, len);
    buf[len] = 0;

    p = buf;
    /* skip schema */
    p = strchr(buf, ':');
    if (p == NULL || (p[1] != '/') || (p[2] != '/')){
	free(buf);
	free(rs);
	return NULL;
    }
    p += 3; /* skip "://" */

    /* get hostname */
    hostname_start = p;
    p = strchr(p, '/');
    if (p ==  NULL){
	free(buf);
	free(rs);
	return NULL;
    }
    p[0] = 0;
    strncpy(rs->hostname, hostname_start, sizeof(rs->hostname)-1);

    p += 1; /* skip "/" */

    path_start = p;

    /*  get path and query string */
    p = strchr(p, '?');
    if (p == NULL){
	strncpy(rs->path, path_start, sizeof(rs->path));
    } else {
	p[0] = 0;
	p += 1;
	strncpy(rs->path, path_start, sizeof(rs->path));
	strncpy(rs->query, p, sizeof(rs->query));
    }

    /* parse path */
    strcpy(buf, rs->path);

    tokstr = buf;
    for (toknum=0;toknum<3;toknum++) {
	token = strtok_r(tokstr, "/", &tokptr);
	tokstr = NULL;
	if (token == NULL)
	    break;

	if (toknum == 0){
	    strncpy(rs->category, token, sizeof(rs->category)-1);
	} else if (toknum == 1){
	    strncpy(rs->group, token, sizeof(rs->group)-1);
	} else if (toknum == 2){
	    strncpy(rs->port, token, sizeof(rs->port)-1);
	}
    }

    log_debug("== Parsed URI");
    log_debug("    host:   %s", rs->hostname);
    log_debug("    path:   %s", rs->path);
    log_debug("    query:  %s", rs->query);
    log_debug("    * cat:  %s", rs->category);
    log_debug("    * grp:  %s", rs->group);
    log_debug("    * port: %s", rs->port);

    free(buf);
    return rs;
}

/**********************************************************************************/

int cook_rtsp_rtp_info(char *dstbuf, int bufsize, struct rtsp_requested_stream *rs, uint32_t rtp_seq)
{
    if (rs->query && rs->query[0])
	snprintf(dstbuf, bufsize, "url=rtsp://%s/%s?%s;seq=%d", rs->hostname, rs->path, rs->query, rtp_seq);
    else
	snprintf(dstbuf, bufsize, "url=rtsp://%s/%s;seq=%d", rs->hostname, rs->path, rtp_seq);
    log_info("rtp-info: %s", dstbuf);
    return 0;
}
