#ifndef RTP_H
#define RTP_H

#include "global.h"

struct rtp_header {
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	version:2;
    uint8_t	padding:1;
    uint8_t	extension:1;
    uint8_t	csrc_count:4;

    uint8_t	marker:1;
    uint8_t	payload_type:7;

    uint16_t	sequence:16;
#else
    uint8_t	csrc_count:4;
    uint8_t	extension:1;
    uint8_t	padding:1;
    uint8_t	version:2;

    uint8_t	payload_type:7;
    uint8_t	marker:1;

    uint16_t	sequence:16;
#endif
    uint32_t	timestamp;
    uint32_t	ssrc;
};

#define RTP_HEADER_SIZE (12)
#define RTP_PAYLOAD_TYPE_MP2T (33)
#define RTP_SOURCE_HZ_MP2T (90000)

struct rtcp_header {
    union {
	struct {
#if BYTE_ORDER == BIG_ENDIAN
	    uint8_t	version:2;
	    uint8_t	padding:1;
	    uint8_t	reports_count:5;
#else
	    uint8_t	reports_count:5;
	    uint8_t	padding:1;
	    uint8_t	version:2;
#endif
	    uint8_t	packet_type:8;
	    uint16_t	length4:16;
	};
	uint32_t	dw0;
    };
    uint32_t	sender_ssrc;
};

struct rtcp_receiver_report {
    uint32_t	ssrc;

#if BYTE_ORDER == BIG_ENDIAN
    uint32_t	fraction_lost:8;
    int32_t	cumulative_lost:24;
#else
    uint32_t	fraction_lost:8;
    int32_t	cumulative_lost:24;
#endif
    uint32_t	extended_highest_seq;
    uint32_t	interarrival_jitter;
    uint32_t	last_sr;
    uint32_t	delay_since_last_sr;
};

#define SIGN_EXTEND_24BIT32(x) ((x) | (!!((x) & 0x800000) * 0xff000000))

#if BYTE_ORDER == BIG_ENDIAN
# define RTCP_RR_CUMULATIVE_LOST(_x_) (SIGN_EXTEND_24BIT32((_x_)->cumulative_lost))
#else
# define RTCP_RR_CUMULATIVE_LOST(_x_) (SIGN_EXTEND_24BIT32(ntohl(((_x_)->cumulative_lost)<<8)))
#endif

#define RTCP_TYPE_SENDER_REPORT (200)
#define RTCP_TYPE_RECEIVER_REPORT (201)
#define RTCP_TYPE_SOURCE_REPORT (202)
#define RTCP_TYPE_BYE (203)

#endif /* RTP_H */
