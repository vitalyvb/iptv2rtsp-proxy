#ifndef CONFIG_H
#define CONFIG_H

#define PROGRAM_NAME "iptv2rtsp-proxy"

#define DEFAULT_CONFIG_FILE ("/etc/" PROGRAM_NAME ".conf")

#define DEFAULT_PID_FILE ("/var/run/" PROGRAM_NAME ".pid")

/* mpeio */
#define MPEGIO_NOT_USED_TIMEOUT (60.0)

#define MPEGIO_DEFAULT_RINGBUF_SIZE (1024*1024)
#define MPEGIO_MAX_STREAM_DELAY (100)

/* rtsp */
#define WARN_JITTER_VALUE_RTCP_RR (900) /* 10ms for 90KHz standart MP2T clock rate */
#define RTSP_CHECK_SESSION_TIMEOUTS_ITER (0.5)
#define RTSP_CHECK_SESSIONS_ROUND (5.0)
#define NO_RTCP_SESSION_TIMEOUT (25.0)

#define RTSP_SESSION_TIMEOUT (60.0)

#define HTTP_SESS_HASHSIZE (0x100)
#define RTSP_SESS_HASHSIZE (0x100)
#define RTSP_MPEGIO_HASHSIZE (0x40)

#define RTP_CLIENT_PORT_BASE (2000) /* clients udp base port number, must be even */
#define RTP_CLIENT_PORT_INCR (2) /* port increments if ports are used already, must be even */
#define RTP_CLIENT_PORT_MAX (RTP_CLIENT_PORT_BASE + 1000) /* maximum port number when determining port for the client */

/* psi */
#define PSI_PID_HASHMASK (0xf)
#define SECT_REASSEMBL_HASHMASK (0xf)

#endif
