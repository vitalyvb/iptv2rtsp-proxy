#ifndef RTSP_H
#define RTSP_H

#include "global.h"

struct rtsp_server;
typedef struct rtsp_server *RTSP;

int rtsp_load_config(RTSP, dictionary *d);
RTSP rtsp_alloc();
int rtsp_init(RTSP);
void rtsp_cleanup(RTSP);

#endif /* RTSP_H */
