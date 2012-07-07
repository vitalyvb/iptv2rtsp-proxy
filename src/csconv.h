#ifndef CSCONV_H
#define CSCONV_H

#include "global.h"

#define DVB_STR_ENC_DEFAULT (0)
#define DVB_STR_ENC_EXT (0x10)
#define DVB_STR_ENC_UTF8 (0x15)

int csconv_init();
void csconv_cleanup();
void convert_dvb_string(char *src, int src_len, char *dst, int dst_len);

#endif /* CSCONV_H */
