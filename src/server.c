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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#ifdef USE_PTHREADS
# include <pthread.h>
#else
# include <sched.h>
#endif
#include <pwd.h>
#include <grp.h>

#define LOG_MODULE ("main")
#define LOG_PARAM (NULL)

#include "global.h"
#include "utils.h"
#include "psi.h"
#include "rtsp.h"
#include "csconv.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

int debug = 0;
int verbose = 0;
struct ev_loop *evloop;
ev_tstamp ev_started_at;
char *server_str_id = NULL;
int server_listen_port = 0;
int high_prio_sockets;
int recv_socket_bufsize;

static int log_to_stderr;
static int io_sched_realtime;

static uid_t nopriv_uid = 65534;
static gid_t nopriv_gid = 65534;

static RTSP rtsp_server;

static ev_signal signal_watcher1;
static ev_signal signal_watcher2;
static ev_signal signal_watcher3;
static ev_signal signal_watcher4;

static void usage()
{
    printf("IPTV to RTSP proxy Version %s\n", VERSION);
    printf("Usage: " PROGRAM_NAME " [options]\n");
    printf("options:\n");
    printf("\t-h\tthis screen\n");
    printf("\t-v\tverbose\n");
    printf("\t-d\tdon't fork and log some debug info\n");
    printf("\t-s\tserver id (IP address for SDP origin)\n");
    printf("\t-l\trtsp listen port\n");
    printf("\t-f\tstay in foreground\n");
    printf("\t-c file\tconfig file name\n");
    printf("\t-p file\tpid file name\n");
}

void log_message(int level, const char *module, const char *module_dyn, const char *msg, ...)
{
    int res;
    int buffree = 512;
    char *buf, *p;

    va_list args;
    va_start (args, msg);

    p = buf = alloca(buffree+1);

    if (!log_to_stderr){
	if (module_dyn)
	    res = snprintf(p, buffree, "%s[%s]: ", module, module_dyn);
	else
	    res = snprintf(p, buffree, "%s: ", module);
    } else {
	if (module_dyn)
	    res = snprintf(p, buffree, PROGRAM_NAME"[%d] %s(%s): ", getpid(), module, module_dyn);
	else
	    res = snprintf(p, buffree, PROGRAM_NAME"[%d] %s: ", getpid(), module);
    }
    if (res < 0)
	return;
    buffree -= res;
    p += res;

    res = vsnprintf(p, buffree, msg, args);
    if (res < 0)
	return;
    if (res > buffree)
	res = buffree;
    buffree -= res;
    p += res;

    /* TODO protect with a mutex */
    if (!log_to_stderr){
	syslog(level, "%s", buf);
    } else {
	if (buffree > 0){
	    p[0] = '\n';
	    p[1] = 0;
	    buffree -= 1;
	    p++;
	} else {
	    strcpy(&p[-4], "...\n");
	}
	res = fwrite(buf, sizeof(char), p-buf, stderr);
    }
    va_end (args);
}

void log_data(int level, const char *module, const char *module_dyn, const char *msg, const void *_data, int len)
{
#define BUFLEN (128*3)
    const unsigned char *data = (const unsigned char *)_data;
    char buf[BUFLEN+1];
    int i, chars, bufpos=0;

    if (data == NULL) {
	strcpy(buf, "(null)");
    } else if (len <= 0) {
	strcpy(buf, "NONE");
    } else if (len > 0) {
	for (i=0; i<len-1; i++){
	    chars = snprintf(&buf[bufpos], BUFLEN-bufpos, "%02x ", data[i]);
	    if (chars < 0)
		return;
	    bufpos += chars;
	    if (bufpos >= BUFLEN-8){
		strncpy(&buf[bufpos], "...", BUFLEN-bufpos);
		buf[BUFLEN] = 0;
		bufpos = BUFLEN;
		break;
	    }
	}
	snprintf(&buf[bufpos], BUFLEN-bufpos, "%02x", data[i]);
    }

    log_message(level, module, module_dyn, msg, buf);
#undef BUFLEN
}

static void get_pw_uids(char *nopriv_uid_name, char *nopriv_gid_name)
{
    struct passwd *pw;
    struct group *grp;

    pw = getpwnam(nopriv_uid_name);
    if (pw == NULL){
	log_error("user '%s' not found", nopriv_uid_name);
	return;
    }

    nopriv_uid = pw->pw_uid;
    nopriv_gid = pw->pw_gid;

    grp = getgrnam(nopriv_gid_name);
    if (grp == NULL){
	log_error("group '%s' not found", nopriv_gid_name);
	return;
    }

    nopriv_gid = grp->gr_gid;
}

int load_config(const char *filename)
{
    char *nopriv_uid_name;
    char *nopriv_gid_name;
    dictionary* ini_dict;
    const char *s;

    ini_dict = iniparser_load(filename);

    if (ini_dict == NULL){
	log_error("Unable to load config file '%s': %s", filename, strerror(errno));
    }

    io_sched_realtime = iniparser_getboolean(ini_dict, "sched:realtime_io", 0);

    if (server_str_id == NULL){
	s = iniparser_getstring(ini_dict, "general:server_id", "192.168.0.1");
	server_str_id = strdup(s);
    }

    high_prio_sockets = iniparser_getboolean(ini_dict, "general:high_prio_sockets", 1);

    recv_socket_bufsize = iniparser_getint(ini_dict, "general:socket_rxbufsize", 0);

    s = iniparser_getstring(ini_dict, "general:user", "nobody");
    nopriv_uid_name = xmalloc(strlen(s)+1);
    strcpy(nopriv_uid_name, s);

    s = iniparser_getstring(ini_dict, "general:group", "nobody");
    nopriv_gid_name = xmalloc(strlen(s)+1);
    strcpy(nopriv_gid_name, s);

    get_pw_uids(nopriv_uid_name, nopriv_gid_name);
    xfree(nopriv_uid_name);
    xfree(nopriv_gid_name);

    if (rtsp_load_config(rtsp_server, ini_dict))
	return 1;

    if (ini_dict)
	iniparser_freedict(ini_dict);

    return 0;
}

/******************************************************************************/

static void setup_io_prio()
{
    int policy;
    struct sched_param sched_param;
    int res;

#ifdef USE_PTHREADS
    if (io_sched_realtime){
	sched_param.sched_priority = 10;
	res = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sched_param);
	if (res){
	    log_error("error setting realtime priority: %s", strerror(errno));
	}
    }

    memset(&sched_param, 0, sizeof(struct sched_param));
    res = pthread_getschedparam(pthread_self(), &policy, &sched_param);
    if (res == 0){
	log_info("IO thread sched: %s, priority: %d",
	    (policy == SCHED_FIFO) ? "FIFO" :
	    (policy == SCHED_RR) ? "RR" :
	    (policy == SCHED_OTHER) ? "OTHER" :
	    "UNK",
	    sched_param.sched_priority);
    }
#else

    if (io_sched_realtime){
	sched_param.sched_priority = 10;
	res = sched_setscheduler(0, SCHED_FIFO, &sched_param);
	if (res){
	    log_error("error setting realtime priority: %s", strerror(errno));
	}
    }

    policy = sched_getscheduler(0);
    if (policy >= 0){
	log_info("IO sched: %s",
	    (policy == SCHED_FIFO) ? "FIFO" :
	    (policy == SCHED_RR) ? "RR" :
	    (policy == SCHED_OTHER) ? "OTHER" :
	    "UNK");
    }

#endif
}

static void sig_term_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    ev_break (loop, EVBREAK_ALL);
}

static void sig_ignore_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    /* ignore */
}

static int pidfd = -1;

static void clean_pid_file()
{
    int tmp;

    if (pidfd >= 0){
	tmp = ftruncate(pidfd, 0);
	close(pidfd);
	pidfd = -1;
    }
}

static int write_pid_file(const char *filename)
{
    char buf[16];
    int len;

    len = snprintf(buf, 16, "%d\n", getpid());
    len = len > 16 ? 16 : len;

    pidfd = open(filename, O_WRONLY|O_CREAT, 0644);
    if (pidfd < 0){
	log_error("error opening pid file '%s': %s", filename, strerror(errno));
	return 1;
    }

    if (write(pidfd, buf, len) != len){
	log_error("error writing pid file: %s", strerror(errno));
	close(pidfd);
	pidfd = -1;
	return 1;
    }

    if (atexit(clean_pid_file)){
	log_error("can not regiser function to remove pidfile on exit");
	close(pidfd);
	pidfd = -1;
    }
    return 0;
}

static void elevate_privileges()
{
    if (geteuid() == 0 && getuid() != 0){
	/* setting FIFO scheduler can fail without this */
	setuid(0);
    }
}

static void drop_privileges()
{
    gid_t oldgid = getegid();
    uid_t olduid = geteuid();

    if (geteuid() == 0){

	if (pidfd >= 0){
	    if (fchown(pidfd, nopriv_uid, nopriv_gid))
		log_warning("can not change pid file owner: %s", strerror(errno));
	}

	setgroups(1, &nopriv_gid);

	if (setregid(nopriv_gid, nopriv_gid)){
	    log_error("failed to drop group privileges: %s", strerror(errno));
	}

	if (setreuid(nopriv_uid, nopriv_uid)){
	    /* real user change can fail due to FIFO process priority */
	    log_error("failed to drop full user privileges: %s", strerror(errno));
	    log_error("probably you have to increase /sys/kernel/uids/%d/cpu_rt_runtime or setup cgroups", nopriv_uid);
	    if (seteuid(nopriv_uid))
		log_error("failed to drop effective user privileges: %s", strerror(errno));
	    else
		log_info("changed effective user id successfully");
	}

	if (((oldgid != nopriv_gid) && (getegid() != nopriv_gid)) ||
	    ((olduid != nopriv_uid) && (geteuid() != nopriv_uid))){
	    log_warning("failed to drop privileges");
	} else {
	    log_info("dropped privileges");
	}
    }
}

int main(int argc, char **argv)
{
    int do_fork = 1;
    char *config_fn = DEFAULT_CONFIG_FILE;
    char *pid_fn = DEFAULT_PID_FILE;
    int c;

    evloop = EV_DEFAULT;
    ev_started_at = ev_time();

    opterr = 0;

    while ((c = getopt (argc, argv, "vhdfc:p:s:l:")) != -1) {
	switch (c) {
	case 'v':
	    verbose++;
	    break;
	case 'h':
	    usage(0);
	    return 0;
	case 'd':
	    debug = 1;
	    do_fork = 0;
	    break;
	case 'f':
	    do_fork = 0;
	    break;
	case 'c':
	    config_fn = optarg;
	    break;
	case 'p':
	    pid_fn = optarg;
	    break;
	case 's':
	    server_str_id = strdup(optarg);
	    break;
	case 'l':
	    server_listen_port = atoi(optarg);
	    if (server_listen_port < 1 || server_listen_port > 65534){
		fprintf (stderr, "Invalid listen port: %s.\n", optarg);
		return 1;
	    }
	    break;
	case '?':
	    if ((optopt == 'c') || (optopt == 'p') || (optopt == 's') || (optopt == 'l'))
		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	    else if (isprint (optopt))
		fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	    else
		fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);

	    return 1;

	default:
	    usage();
	    return 1;
	}
    }

    if (optind < argc) {
	fprintf (stderr, "Unknown option: %s.\n", argv[optind]);
	return 1;
    }


    rtsp_server = rtsp_alloc();
    if (!rtsp_server){
	return 0;
    }

    log_to_stderr = !do_fork;

    if (!log_to_stderr)
	openlog(PROGRAM_NAME, LOG_PID, LOG_DAEMON);

    if (load_config(config_fn)) {
	fprintf (stderr, "Error loading config file.\n");
	return 2;
    }

    my_random_init();

    if (do_fork){
	log_debug("forking...");
	if (daemon(0, 0)){
	    log_error("daemonize failed: %s", strerror(errno));
	    return -1;
	}
	if (write_pid_file(pid_fn)){
	    log_warning("failed to create pid file");
	}
	ev_loop_fork(evloop);
    }


    if (!do_fork) {
	ev_signal_init (&signal_watcher1, sig_term_cb, SIGINT);
	ev_signal_start (evloop, &signal_watcher1);
    }

    ev_signal_init (&signal_watcher2, sig_term_cb, SIGTERM);
    ev_signal_start (evloop, &signal_watcher2);

    ev_signal_init (&signal_watcher3, sig_ignore_cb, SIGHUP);
    ev_signal_start (evloop, &signal_watcher3);

    ev_signal_init (&signal_watcher4, sig_ignore_cb, SIGPIPE);
    ev_signal_start (evloop, &signal_watcher4);


    if (csconv_init()){
	return 0;
    }
    if (rtsp_init(rtsp_server)){
	csconv_cleanup();
	return 0;
    }

    elevate_privileges();

    setup_io_prio();

    drop_privileges();

    log_info("starting...");

    ev_run(evloop, 0);

    log_info("cleaning up...");

    rtsp_cleanup(rtsp_server);

    csconv_cleanup();

    if (server_str_id)
	free(server_str_id);

    log_info("exiting...");

    if (!log_to_stderr)
	closelog();

    return 0;
}
