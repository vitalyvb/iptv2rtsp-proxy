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
#include <errno.h>

#include "ebb.h"
#include "jhash.h"

#define LOG_MODULE ("rtcp")
#define LOG_PARAM (NULL)

#include "global.h"
#include "mpegio.h"
#include "utils.h"
#include "rtp.h"
#include "rtcp.h"
#include "rtspsess.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

#define this (_this)
#define THIS RTCP _this

/***********************************************************************/

static void ev_rtcp_input_handler(struct ev_loop *loop, ev_io *w, int revents)
{
    char buf[2048];
    THIS = (RTCP) w->data;
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

		this->handler(this->handler_param, ntohl(rr->ssrc),
			    ntohl(rr->interarrival_jitter),
			    RTCP_RR_CUMULATIVE_LOST(rr),
			    rr->fraction_lost,
			    ntohl(rr->interarrival_jitter));

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

int rtcp_setup(THIS, handle_rtcp_data handler, void *param, struct in_addr *listen_addr, int listen_port)
{
    struct sockaddr_in addr;
    int res;
    int fd;

    this->handler = handler;
    this->handler_param = param;

    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
	log_error("can not create rtcp recv socket: %s", strerror(errno));
	return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    addr.sin_addr.s_addr = listen_addr->s_addr;

    res = bind(fd, (struct sockaddr*)&addr, sizeof(addr));

    if (res < 0){
	log_error("can not bind to rtcp socket: %s", strerror(errno));
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
