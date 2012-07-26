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
#include <errno.h>
#include <arpa/inet.h>

#define LOG_MODULE ("mpegio")
#define LOG_PARAM (this->identifier)

#include "global.h"
#include "mpegio.h"
#include "rtp.h"
#include "psi.h"
#include "utils.h"

#include <linux/errqueue.h>
#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

#define RINGBUF_BB_SIZE 2048

struct mp2t_cc_check {
    uint8_t cc:4;
    uint8_t active:1;
    uint8_t _pad:3;
};


struct pkt_descriptor {
    struct pkt_descriptor *next;
    ev_tstamp tv;

    union {
	struct s_mpeg {
	    int packets;
	    uint32_t stream_pos;
	    uint8_t *data;
	} mpeg;
    };
};

struct mpegio_client {
    struct mpegio_client *next;

    int id;
    int active;

    uint32_t ssrc;
    struct sockaddr_in send_dest;

    uint16_t rtp_seq;
};

struct mpegio_stream {

    int initialized;
    char *identifier;

    /* tunables */
    struct in_addr addr;
    uint16_t port;
    int ringbuf_size;
    int opt_so_rcvbuf;
    int max_stream_delay;

    mpegeio_on_send_error on_send_error;
    void *cbdata;

    /* working state */
    int recv_fd;
    int send_fd;

    ev_io input_watcher;
    ev_timer sendtime_watcher;
    ev_timer suicide_timer;

    ev_tstamp time_previous_packet;
    ev_tstamp time_recv_started;
    ev_tstamp time_recv_send;
    int start_streaming;


    ev_tstamp inactive_since;
    int active;
    int latest_client_id;
    struct mpegio_client *clients_list;
    struct mpegio_client *clients_tail;
    int active_clients;
    int clients;

    /* stream information */
    PSI psi;

    /* buffer and io stuff */
    uint8_t *ringbuf;
    uint8_t *ringbuf_bb;
    int ringbuf_start;
    int ringbuf_end;

    uint32_t abs_stream_pos;

    struct pkt_descriptor *descr_head;
    struct pkt_descriptor *descr_tail;
    struct pkt_descriptor *pool_descr_head;

    struct mp2t_cc_check cc_check[MPEG_TOTAL_PIDS];
};

#define this (_this)
#define THIS MPEGIO _this

/************************************************************************/

static void mpegio_cleanup(THIS);

/************************************************************************/

int mpegio_configure(MPEGIO _this, const struct mpegio_config *config)
{
    this->port = config->port;
    this->send_fd = config->send_fd;

    this->on_send_error = config->on_send_error;
    this->cbdata = config->cbdata;

    memcpy(&this->addr, &config->addr, sizeof(struct in_addr));

    if (config->init_buf_size >= 64*1024)
	this->ringbuf_size = config->init_buf_size;
    else
	this->ringbuf_size = MPEGIO_DEFAULT_RINGBUF_SIZE;

    if (config->streaming_delay >= 10 && config->streaming_delay < 1800*1000)
	this->max_stream_delay = config->streaming_delay;
    else
	this->max_stream_delay = MPEGIO_MAX_STREAM_DELAY;

    return 0;
}

/************************************************************************/

static void descr_free_list(THIS, struct pkt_descriptor *list)
{
    struct pkt_descriptor *head, *next;

    head = list;
    while (head) {
	next = head->next;
	head->next = NULL;
	xfree(head);
	head = next;
    }
}

static void descr_release(THIS, struct pkt_descriptor *d)
{
    d->next = this->pool_descr_head;
    this->pool_descr_head = d;
}

static void descr_release_all(THIS)
{
    struct pkt_descriptor *d, *next;

    d = this->descr_head;
    while (d){
	next = d->next;

	d->next = this->pool_descr_head;
	this->pool_descr_head = d;

	d = next;
    }
    this->descr_head = NULL;
    this->descr_tail = NULL;
}

static struct pkt_descriptor *descr_alloc(THIS)
{
    struct pkt_descriptor *d;

    if (this->pool_descr_head){
	d = this->pool_descr_head;
	this->pool_descr_head = d->next;
    } else {
	d = xmalloc(sizeof(struct pkt_descriptor));
    }

    d->next = NULL;

    return d;
}

static void descr_append(THIS, struct pkt_descriptor *d)
{
    if (this->descr_tail) {
	this->descr_tail->next = d;
	this->descr_tail = d;
    } else {
	this->descr_head = d;
	this->descr_tail = d;
    }
}

/***********************************************************************************/

/* make this a pool to reduce memory fragmentation
 * and to lower malloc() overhead
 */

static void ring_buffer_release(THIS)
{
    this->ringbuf_start = 0;
    this->ringbuf_end = 0;
    descr_release_all(this);

    free(this->ringbuf);
    this->ringbuf = NULL;
}

static int ring_buffer_setup(THIS)
{
    assert(this->descr_head == NULL);
    assert(this->ringbuf == NULL);

    this->ringbuf = xmalloc(this->ringbuf_size);
    if (this->ringbuf == NULL)
	return -1;

    return 0;
}

/***********************************************************************************/

static void handle_error_report_packet(THIS, struct sockaddr *sockaddr, int in_errno, uint8_t *data, int datasize)
{
    struct mpegio_client *client;
    struct rtp_header *hdr;
    uint8_t *payload;
    int payload_size;
    uint32_t ssrc;

    if (datasize < RTP_HEADER_SIZE)
	return;

    hdr = (struct rtp_header *)data;
    payload = data+RTP_HEADER_SIZE;
    payload_size = datasize - RTP_HEADER_SIZE;

    if (payload_size < 1 || payload[0] != MPEG_SYNC)
	/* not mp2ts payload*/
	return;

    if (hdr->version != 2 ||
		hdr->padding ||
		hdr->extension ||
		hdr->csrc_count ||
		hdr->marker ||
		hdr->payload_type != RTP_PAYLOAD_TYPE_MP2T)
	/* not ours packet, for sure */
	return;

    ssrc = ntohl(hdr->ssrc);

    if (this->on_send_error){
	this->on_send_error(this->cbdata, ssrc, in_errno);
    }

}


static void handle_send_error(THIS, int fd)
{
    struct sockaddr_storage sockaddr;
    uint8_t data[32];
    char aux[2048];
    char ipaddr[32];
    struct msghdr msg;
    struct iovec vec;

    int res;
    struct cmsghdr *cmsg;
    struct sock_extended_err *eerr;

    vec.iov_base = data;
    vec.iov_len = sizeof(data);

    memset(&sockaddr, 0, sizeof(struct sockaddr_storage));
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_name = &sockaddr;
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = aux;
    msg.msg_controllen = sizeof(aux);

    res = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);

    if (res <= 0) {
	log_debug("recvmsg MSG_ERRQUEUE failed with:%d errno:%d", res, errno);
	return;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVERR) {
	    eerr = (struct sock_extended_err*) CMSG_DATA(cmsg);

	    if (SO_EE_OFFENDER(eerr)->sa_family == AF_INET){
		struct in_addr *addr = &((struct sockaddr_in *)SO_EE_OFFENDER(eerr))->sin_addr;

		if (inet_ntop(AF_INET, addr, ipaddr, sizeof(ipaddr)) == NULL){
		    strcpy(ipaddr, "UNKNOWN");
		}
	    } else {
		strcpy(ipaddr, "UNKNOWN");
	    }

	    if (eerr->ee_origin != SO_EE_ORIGIN_NONE && eerr->ee_errno != 0){
		log_warning("extended error errno: %d origin: %d type: %d code: %d reported by: %s data: %*T",
		    eerr->ee_errno, eerr->ee_origin, eerr->ee_type, eerr->ee_code,
		    ipaddr,
		    (res>16)?16:res, data);

		handle_error_report_packet(this, (struct sockaddr *)&sockaddr, eerr->ee_origin, data, res);
		break;
	    }
	}
    }

}

static void send_to_clients(THIS, uint8_t *buffer, int length, uint32_t timestamp)
{
    /* send same data to all clients changind rtp header only */
    struct mpegio_client *client = this->clients_list;
    uint8_t *packet = this->ringbuf_bb;
    struct rtp_header *real_rtp_header;
    int packet_size;
    int res;

    real_rtp_header = (struct rtp_header *)packet;
    memcpy(packet+RTP_HEADER_SIZE, buffer, length);
    packet_size = length+RTP_HEADER_SIZE;

    /* If you change this, also update the error handler above */
    real_rtp_header->version = 2;
    real_rtp_header->padding = 0;
    real_rtp_header->extension = 0;
    real_rtp_header->csrc_count = 0;
    real_rtp_header->marker = 0;
    real_rtp_header->payload_type = RTP_PAYLOAD_TYPE_MP2T;


    /* there are at least two other options to accomplist this task
     * presumably more efficienly:
     *
     * 1. vmsplice()/tee()/splice() - saves many userspace->kernel memcpys,
     *    uses many syscalls, see:
     *    http://stackoverflow.com/questions/3445566/writing-to-multiple-file-descriptors-with-a-single-function-call
     *    http://yarchive.net/comp/linux/splice.html
     *
     * 2. mmapped PF_PACKET - many memcpys in userspace will be required(?) and a single syscall,
     *    see
     *    http://wiki.ipxwarzone.com/index.php5?title=Linux_packet_mmap
     */
    while (client){
	if (client->active != MPEGIO_CLIENT_PLAY){
	    client = client->next;
	    continue;
	}

	real_rtp_header->sequence = htons(client->rtp_seq++);
	real_rtp_header->timestamp = htonl(timestamp);
	real_rtp_header->ssrc = htonl(client->ssrc);

	res = sendto(this->send_fd, packet, packet_size, 0,
			(struct sockaddr*)&client->send_dest, sizeof(client->send_dest));

	if (res != packet_size){
	    /* Because of deferred error reporting for UDP sockets (error is reported
	     * after ICMP message received to the next first sendto() call)
	     * the error result of the latest call does NOT mean that error occured
	     * for this exact client - in fact it occured for some recent client 
	     * for which sendto() returned success.
	     *
	     * Further error analysis if required to reliably determine a client this
	     * error relates.
	     */
	    handle_send_error(this, this->send_fd);
	}

	client = client->next;
    }
}

static uint32_t ev_tstamp_to_mp2t_freq(ev_tstamp ts)
{
    /* Some architectures e.g. MIPS soft-float casts double to float with
     * saturation, and others (like x86-64) with wrap-around.
     *
     * To keep things simple and hopefully portable, this is the way to go.
     */
    ev_tstamp tdiff = ts - ev_started_at;
    uint32_t secs, fraction;

    secs = tdiff;
    fraction = (tdiff - secs) * RTP_SOURCE_HZ_MP2T;

    return secs * RTP_SOURCE_HZ_MP2T + fraction;
}

static void mpegio_output_handler(THIS)
{
    struct pkt_descriptor *descr;
    int continue_send=0;

    if (this->time_recv_send == 0.0) {
	this->time_recv_send = ev_now(evloop) - this->time_recv_started;
	log_info("buffering delay: %f", this->time_recv_send);
    }

    if (unlikely(this->descr_head == NULL)){
	log_error("wtf, no descr_head list");
	return;
    }

    do {
	descr = this->descr_head;

	if (verbose > 2)
	    log_info("sending out packet %d %d", this->ringbuf_start, this->ringbuf_end);

	send_to_clients(this, descr->mpeg.data, descr->mpeg.packets*MPEG_PKT_SIZE, ev_tstamp_to_mp2t_freq(descr->tv));

	this->ringbuf_start += descr->mpeg.packets*MPEG_PKT_SIZE;
	if (this->ringbuf_start+MPEG_PKT_SIZE > this->ringbuf_size){
	    this->ringbuf_start = 0;
	}

	/**/

	continue_send = 0;
	this->descr_head = descr->next;
	if (likely(this->descr_head)) {
	    if (this->descr_head->tv == descr->tv){
		/* same timestamp */
		continue_send = 1;
	    }
	}
	descr_release(this, descr);

    } while (continue_send);


    if (this->descr_head) {
	double target_delay;

	target_delay =  (this->descr_head->tv + this->time_recv_send) - ev_now(evloop);

	/* It is possible that we missed next packet's target send time -
	 * ignore such situations - slightly delayed packets once in a
	 * while are harmless.
	 * 
	 * This also gives a chance to receive data with correct timestams.
	 */

	if (target_delay > 30.0){
	    /* delay is too big for  conventional video streaming,
	     * probably heavy clock skew occured
	     */
	    target_delay = 30.0;
	}

	ev_timer_set(&this->sendtime_watcher, target_delay, 0.0);
	ev_timer_start(evloop, &this->sendtime_watcher);
    } else {
	log_info("no data to send. stopping");

	this->descr_tail = NULL;

	this->time_recv_started = 0.0;
	this->time_recv_send = 0.0;
	this->start_streaming = 0;

	ring_buffer_release(this);
    }
}

static int cc_checker(THIS, int pid, int payload_present, int cc)
{
    int expect;

    if (pid < 0 || pid >= MPEG_TOTAL_PIDS)
	return -1;

    assert(sizeof(this->cc_check[0]) == 1);

    if (this->cc_check[pid].active){
	/* Incremented only if payload is present
	 */
	expect = MPEG_HDR_CNT_NEXT(this->cc_check[pid].cc - 1*(!payload_present));
	if (expect != cc){
	    log_warning("TS discontinuity (received %d, expected %d) for PID %d", cc, expect, pid);
	}
    } else {
	this->cc_check[pid].active = 1;
    }
    this->cc_check[pid].cc = cc;
    return 0;
}

static int mpegio_input_handler(THIS)
{
    uint8_t *buf = this->ringbuf_bb;
    int packets = 0;
    int len;

    len = recv(this->recv_fd, buf, RINGBUF_BB_SIZE, MSG_DONTWAIT);

    if (unlikely(this->ringbuf == NULL)){
	if (ring_buffer_setup(this)){
	    return -1;
	}
    }

    while (len>0) {
	struct pkt_descriptor *d;
	int sync_loss = 0;
	int pos = 0;
	uint8_t *datastart = NULL;
	int new_ringbuf_end, dst_start;
	int count = 0;
	uint16_t pkt_flags, pid;


	d = descr_alloc(this);

	d->tv = ev_now(evloop);

	this->abs_stream_pos += len;

	if (verbose > 1)
	    log_info("got %d bytes, %f", len, d->tv);

	/* it is possible that target io delay will be much larger than max_stream_delay
	 *
	 * this happens if input streaming started, and almost immidiately
	 * stopped (before we started to send data), buffer timer continues to
	 * run...
	 *
	 * so we check here if at most 200ms have passed since last packet
	 * arrived if streaming is not active
	 *
	 */

	if (!this->start_streaming && (this->time_recv_started != 0.0)){
	    ev_tstamp diff;

	    diff = d->tv - this->time_previous_packet;

	    if (diff > 0.2){
		log_warning("delay between packets is too large: %f, resetting", diff);
		descr_release(this, d);
		this->time_recv_started = 0.0;
		this->time_recv_send = 0.0;
		ring_buffer_release(this);
		break;
	    }

	}
	this->time_previous_packet = d->tv;

	if (this->time_recv_started == 0.0) {
	    this->time_recv_started = d->tv;
	}

	while (pos < len) {
	    if (buf[pos] != MPEG_SYNC){
		if (sync_loss == 0)
		    log_warning("mpeg sync lost");
		sync_loss = 1;
		pos++;
	    } else {
		sync_loss = 0;
		if (pos+MPEG_PKT_SIZE > len) {
		    log_warning("mpeg short packet received");
		    break;
		}

		if (verbose > 2)
		    log_info("%02x %02x %02x %02x  %d %d %d %x %x %d %d %x", buf[pos], buf[pos+1], buf[pos+2], buf[pos+3],
			!!MPEG_HDR_TEI(&buf[pos]), !!MPEG_HDR_PUS(&buf[pos]), !!MPEG_HDR_TP(&buf[pos]),
			MPEG_HDR_PID(&buf[pos]), MPEG_HDR_SC(&buf[pos]), !!MPEG_HDR_AF(&buf[pos]),
			!!MPEG_HDR_PD(&buf[pos]), MPEG_HDR_CNT(&buf[pos]));

		pid = MPEG_HDR_PID(&buf[pos]);

		if (MPEG_HDR_TEI(&buf[pos])) {
		    log_warning("dropping mpeg packet with transport error flag set. looks like pid is %d", pid);
		    pos += MPEG_PKT_SIZE;
		    continue;
		}

		if (pid == MPEG_RESERVED_PID){
		    pos += MPEG_PKT_SIZE;
		    continue;
		}

		cc_checker(this, pid, MPEG_HDR_PD(&buf[pos]), MPEG_HDR_CNT(&buf[pos]));

		if (pid == MPEG_PID_PAT) {
		    psi_submit_for_reassemply(this->psi, pid, PSI_PID_PAT_FLAGS, &buf[pos]);
		} else if (pid == MPEG_PID_SDT) {
		    psi_submit_for_reassemply(this->psi, pid, PSI_PID_SDT_FLAGS, &buf[pos]);
		} else {
		    pkt_flags = psi_pid_lookup_flags(this->psi, pid);
		    if (pkt_flags & PSI_PID_NEEDS_REASSEMBLY)
			psi_submit_for_reassemply(this->psi, pid, pkt_flags, &buf[pos]);
		}

		/* store mpeg packet in the ring buffer and check for overflows */

		new_ringbuf_end = this->ringbuf_end;
		if (new_ringbuf_end+MPEG_PKT_SIZE > this->ringbuf_size){
		    /* roll over 0 */
		    dst_start = 0;
		    new_ringbuf_end = MPEG_PKT_SIZE;
		    if (this->ringbuf_start == 0){
			log_error("ring buffer overflow. input data discarded");
			break;
		    }

		    /* commit descriptor, reset counters/state */
		    if (count > 0){
			d->mpeg.packets = count;
			d->mpeg.data = datastart;
			d->mpeg.stream_pos = this->abs_stream_pos;

			descr_append(this, d);

			d = descr_alloc(this);
			count = 0;
			datastart = NULL;
			d->tv = ev_now(evloop);
		    }

		} else {
		    dst_start = new_ringbuf_end;
		    new_ringbuf_end += MPEG_PKT_SIZE;

		    if (this->ringbuf_end != 0 && this->ringbuf_start != 0){
			if (this->ringbuf_end <= this->ringbuf_start && new_ringbuf_end > this->ringbuf_start) {
			    log_error("ring buffer overflow. input data discarded");
			    break;
			}
		    }
		}

		/* copy */

		if (datastart == NULL)
		    datastart = &this->ringbuf[dst_start];

		memcpy(&this->ringbuf[dst_start], &buf[pos], MPEG_PKT_SIZE);
		this->ringbuf_end = new_ringbuf_end;

		count++;
		pos += MPEG_PKT_SIZE;
	    }
	}

	/* commit descriptor */
	if (count > 0){
	    d->mpeg.packets = count;
	    d->mpeg.data = datastart;
	    d->mpeg.stream_pos = this->abs_stream_pos;

	    descr_append(this, d);
	} else {
	    descr_release(this, d);
	}

	/* if buffer is 50% full or `max_stream_delay` seconds have passed, start streaming */
	if (!this->start_streaming) {
	    if (this->ringbuf_end * 2 >= this->ringbuf_size) {
		this->start_streaming = 1;
		mpegio_output_handler(this);
	    } else {
		ev_tstamp diff;

		diff = d->tv - this->time_recv_started;

		if (diff*1000.0 >= this->max_stream_delay){
		    this->start_streaming = 1;
		    mpegio_output_handler(this);
		}
	    }
	}

	if (packets++ >= 3)
	    break;

	len = recv(this->recv_fd, buf, RINGBUF_BB_SIZE, MSG_DONTWAIT);
    }

    return 0;
}

static void ev_mpegio_output_handler(struct ev_loop *loop, ev_timer *w, int revents)
{
    THIS = (MPEGIO) w->data;
    mpegio_output_handler(this);
}

static void ev_mpegio_input_handler(struct ev_loop *loop, ev_io *w, int revents)
{
    THIS = (MPEGIO) w->data;
    mpegio_input_handler(this);
}

struct mpegio_client *mpegio_client_find_by_id(THIS, int client_id)
{
    struct mpegio_client *client = this->clients_list;

    while (client){
	if (client_id == client->id)
	    return client;
	client = client->next;
    }
    return NULL;
}

void mpegio_set_active(THIS, int active)
{
    if (!this->active && active){
	log_info("running");
	ev_timer_stop(evloop, &this->suicide_timer);
	this->inactive_since = 0;
	multicast_group_join(this->recv_fd, &this->addr);
    } else  if (this->active && !active){
	log_info("pausing");
	this->inactive_since = ev_now(evloop);
	multicast_group_leave(this->recv_fd, &this->addr);
    }
    this->active = active;
}

void mpegio_clients_active_changed(THIS)
{
    log_info("clients: %d active: %d", this->clients, this->active_clients);
    if (this->active_clients > 0) {
	if (!this->active){
	    mpegio_set_active(this, 1);
	}
    } else if (this->active_clients == 0) {
	if (this->active){
	    mpegio_set_active(this, 0);
	}
    } else {
	assert(this->active_clients >= 0);
    }
}

int mpegio_client_set_active(THIS, struct mpegio_client *client, int active)
{
    if (client){

	if (!client->active && active){
	    this->active_clients++;
	    mpegio_clients_active_changed(this);
	} else if (client->active && !active){
	    this->active_clients--;
	    mpegio_clients_active_changed(this);
	}

	client->active = active;

	return 0;
    }

    return -1;
}

int mpegio_clientid_set_active(THIS, int client_id, int active)
{
    struct mpegio_client *client = mpegio_client_find_by_id(this, client_id);
    if (client)
	return mpegio_client_set_active(this, client, active);
    return -1;
}

int mpegio_client_get_parameters(THIS, struct mpegio_client *client, int *id, uint32_t *ssrc, uint32_t *rtp_seq)
{
    if (id)
	*id = client->id;

    if (ssrc)
	*ssrc = client->ssrc;

    if (rtp_seq)
	*rtp_seq = client->rtp_seq;

    return 0;
}

int mpegio_clientid_get_parameters(THIS, int client_id, uint32_t *ssrc, uint32_t *rtp_seq)
{
    struct mpegio_client *client = mpegio_client_find_by_id(this, client_id);
    if (client)
	return mpegio_client_get_parameters(this, client, NULL, ssrc, rtp_seq);
    return -1;
}

static void ev_mpegio_suicide_handler(struct ev_loop *loop, ev_timer *w, int revents)
{
    THIS = (MPEGIO) w->data;
    log_info("unused for a long time, freeing resources");
    mpegio_cleanup(this);
}

int mpegio_clientid_destroy(THIS, int client_id)
{
    struct mpegio_client *prev_client = NULL;
    struct mpegio_client *client = this->clients_list;

    while (client){

	if (client_id == client->id){

	    if (prev_client == NULL){
		// head
		this->clients_list = client->next;
	    } else {
		prev_client->next = client->next;
	    }

	    if (this->clients_tail == client){
		this->clients_tail = prev_client;
	    }

	    break;
	}

	prev_client = client;
	client = client->next;
    }

    if (client == NULL){
	log_error("client %d not found", client_id);
	return 0;
    }

    this->clients--;
    if (this->clients == 0)
	ev_timer_start(evloop, &this->suicide_timer);

    if (client->active){
	client->active = 0;
	this->active_clients--;
	mpegio_clients_active_changed(this);
    }

    client->next = NULL;

    free(client);

    return 0;
}

int mpegio_clients_free_all(THIS)
{
    while (this->clients_list){
	mpegio_clientid_destroy(this, this->clients_list->id);
    }
    assert(this->active_clients == 0);
    assert(this->clients == 0);
    return 0;
}

struct mpegio_client *mpegio_client_create(THIS, struct in_addr *dest, uint16_t port, uint32_t ssrc)
{
    struct mpegio_client *client;

    client = xmalloc(sizeof(struct mpegio_client));
    if (client == NULL){
	return NULL;
    }
    memset(client, 0, sizeof(struct mpegio_client));

    client->id = this->latest_client_id++;
    client->active = 0;

    client->send_dest.sin_family = AF_INET;
    client->send_dest.sin_port = htons(port);
    client->send_dest.sin_addr.s_addr = dest->s_addr;

    client->ssrc = ssrc;
    client->rtp_seq = my_rand();

    if (this->clients_tail){
	this->clients_tail->next = client;
	this->clients_tail = client;
    } else {
	this->clients_list = client;
	this->clients_tail = client;
    }

    this->clients++;

    return client;
}

MPEGIO mpegio_alloc()
{
    struct mpegio_stream *_this;

    _this = xmalloc(sizeof(struct mpegio_stream));

    memset(_this, 0, sizeof(struct mpegio_stream));

    this->send_fd = -1;
    this->recv_fd = -1;

    return _this;
}

static int mpegio_setup_name_ident(THIS)
{
    char ipaddr[64];

    if (inet_ntop(AF_INET, &this->addr, ipaddr, sizeof(ipaddr)) == NULL){
	log_error("setup name inet_ntop() failed");
	return -1;
    }

    if (asprintf(&this->identifier, "%s:%d", ipaddr, this->port) < 0){
	log_error("setup name asprintf() failed");
	return -1;
    }

    return 0;
}

int mpegio_is_initialized(MPEGIO _this)
{
    return this->initialized;
}

int mpegio_init(THIS)
{
    struct sockaddr_in addr;
    int res, tmp;
    int fd;
    size_t opt_bufsize;

    if (mpegio_setup_name_ident(this)){
	return -1;
    }

    this->psi = psi_alloc();
    if (!this->psi){
	log_error("psi_alloc failed");
	return -1;
    }

    if (psi_init(this->psi, this->identifier)){
	log_error("psi_init failed");
	return -1;
    }

    this->recv_fd = -1;
    this->opt_so_rcvbuf = 64*1024;

    this->ringbuf = NULL;
    this->ringbuf_bb = xmalloc(RINGBUF_BB_SIZE);

    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
	log_error("can not create recv socket");
	return -1;
    }

    opt_bufsize = this->opt_so_rcvbuf;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt_bufsize, sizeof(opt_bufsize)) == -1){
	log_warning("can not set socket rcvbuf size");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(this->port);
    addr.sin_addr.s_addr = this->addr.s_addr;

    res = bind(fd, (struct sockaddr*)&addr, sizeof(addr));

    if (res < 0){
	log_error("can not bind socket");
	close(fd);
	return -1;
    }

    this->recv_fd = fd;

    memset(this->cc_check, 0, sizeof(this->cc_check));

    ev_io_init(&this->input_watcher, ev_mpegio_input_handler, this->recv_fd, EV_READ);
    this->input_watcher.data = this;
    ev_io_start(evloop, &(this->input_watcher));

    ev_init(&this->sendtime_watcher, ev_mpegio_output_handler);
    this->sendtime_watcher.data = this;

    ev_timer_init(&this->suicide_timer, ev_mpegio_suicide_handler, MPEGIO_NOT_USED_TIMEOUT, 0.0);
    this->suicide_timer.data = this;

    this->initialized = 1;

    return 0;
}

static void mpegio_cleanup(THIS)
{
    ev_timer_stop(evloop, &this->suicide_timer);

    mpegio_clients_free_all(this);

    if (this->recv_fd >= 0){
	ev_timer_stop(evloop, &(this->sendtime_watcher));
	ev_io_stop(evloop, &(this->input_watcher));

	close(this->recv_fd);
	this->recv_fd = -1;
    }

    if (this->psi){
	psi_cleanup(this->psi);
	this->psi = NULL;
    }

    xfree(this->ringbuf_bb);
    this->ringbuf_bb = NULL;

    ring_buffer_release(this);

    descr_release_all(this);
    descr_free_list(this, this->pool_descr_head);
    this->pool_descr_head = NULL;

    if (this->identifier){
	xfree(this->identifier);
	this->identifier = NULL;
    }
    this->initialized = 0;
}

void mpegio_free(THIS)
{
    this->on_send_error = NULL;
    this->cbdata = NULL;

    /* do not close, not ours */
    this->send_fd = -1;

    mpegio_cleanup(this);
    xfree(this);
}

