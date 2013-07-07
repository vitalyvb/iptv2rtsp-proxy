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

#define LOG_MODULE ("url")
#define LOG_PARAM (NULL)

#include "global.h"
#include "url.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

static struct url_requested_stream *alloc_requested_stream()
{
    struct url_requested_stream *rs;
    rs  = xmalloc(sizeof(struct url_requested_stream));
    memset(rs, 0, sizeof(struct url_requested_stream));
    return rs;
}

void free_requested_stream(struct url_requested_stream *s)
{
    free(s);
}

struct url_requested_stream *parse_requested_stream(int type, char *in_text, int len)
{
    char *buf, *p, *tokstr, *token, *tokptr = NULL;
    struct url_requested_stream *rs = alloc_requested_stream();
    char *hostname_start, *path_start;
    int toknum;

    buf = xmalloc(len+1);
    memcpy(buf, in_text, len);
    buf[len] = 0;

    p = buf;
    if (type == REQUEST_URI_RTSP){
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
    } else if (type == REQUEST_URI_HTTP){
	if (len > 0 && p[0] == '/'){
	    p += 1; /* skip "/" */
	}
    } else {
	free(buf);
	free(rs);
	return NULL;
    }

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
