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
#define RTSP_SESS_HASHMASK (0xff)

/* psi */
#define PSI_PID_HASHMASK (0xf)
#define SECT_REASSEMBL_HASHMASK (0xf)

#endif
