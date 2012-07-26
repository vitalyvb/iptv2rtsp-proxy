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

#ifdef HAVE_ICONV
# include <iconv.h>
#endif
#include <errno.h>
#include <ctype.h>

#define LOG_MODULE ("csconv")
#define LOG_PARAM (NULL)

#include "global.h"
#include "csconv.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

struct dvb_encodings {
    int idx;
    int ext;
    const char *encoding;
};

static const struct dvb_encodings dvb_encodings[] = {
    {0x00, 0, "ISO6937"},
    {0x01, 5, "ISO8859-5"},
    {0x03, 7, "ISO8859-7"},
    {0x04, 8, "ISO8859-8"},
    {0x05, 9, "ISO8859-9"},
    {0x06, 10, "ISO8859-10"},
    {0x07, 11, "ISO8859-11"},
    {0x09, 13, "ISO8859-13"},
    {0x0a, 14, "ISO8859-14"},
    {0x0b, 15, "ISO8859-15"},

    /* extended charsets */
    {0x20, 1, "ISO8859-1"},
    {0x21, 2, "ISO8859-2"},
    {0x22, 3, "ISO8859-3"},
    {0x23, 4, "ISO8859-4"},

    {-1, -1, NULL},
};

static void convert_dvb_string_fallback(const char *src, int src_len, char *dst, int dst_len)
{
    int len;

    len = dst_len<src_len ? dst_len:src_len;
    memcpy(dst, src, len);
    if (len < dst_len)
	dst[len] = 0;
}

#ifdef HAVE_ICONV

struct csconv {
    int dvbconv_count;
    iconv_t *dvbconv;
};

static struct csconv csconv;
#define this (&csconv)
#define THIS struct csconv _this

/*************************************************************************/

int csconv_init()
{
    int encodings=0;
    int i;

    memset(this, 0, sizeof(struct csconv));

    for (i=0;dvb_encodings[i].idx>=0;i++){
	if (dvb_encodings[i].idx > encodings)
	    encodings = dvb_encodings[i].idx;
    }

    this->dvbconv_count = encodings+1;

    this->dvbconv = malloc(sizeof(iconv_t)*this->dvbconv_count);
    if (this->dvbconv == NULL)
	return -1;

    for (i=0;i<this->dvbconv_count;i++)
	this->dvbconv[i] = (iconv_t)-1;

    for (i=0;dvb_encodings[i].idx>=0;i++){
	this->dvbconv[dvb_encodings[i].idx] = iconv_open("UTF-8//IGNORE", dvb_encodings[i].encoding);
	if (this->dvbconv[dvb_encodings[i].idx] == (iconv_t)-1){
	    log_error("failed to initialize dvb encoding '%s'", dvb_encodings[i].encoding);
	}
    }

    return 0;
}

void csconv_cleanup()
{
    int i;

    if (this->dvbconv){
	for (i=0;i<this->dvbconv_count;i++){
	    if (this->dvbconv[i] != (iconv_t)-1){
		iconv_close(this->dvbconv[i]);
		this->dvbconv[i] = (iconv_t)-1;
	    }
	}

	free(this->dvbconv);
	this->dvbconv = NULL;
    }
}

void convert_dvb_string(char *src, int src_len, char *dst, int dst_len)
{
    iconv_t conv = (iconv_t)-1;
    char *s=src, *d=dst;
    size_t ls=src_len, ld=dst_len;
    size_t len, i;
    size_t r;

    if (src_len <= 0) {
	dst[0] = 0;
	return;
    }

    switch (src[0]){
    case DVB_STR_ENC_UTF8:
	convert_dvb_string_fallback(src+1, src_len-1, dst, dst_len);
	return;
    case DVB_STR_ENC_EXT:{
	int extid;

	if (src_len < 3){
	    convert_dvb_string_fallback(src, src_len, dst, dst_len);
	    return;
	}

	extid = src[1]<<8 | src[2];

	for (i=0;dvb_encodings[i].idx>0;i++){
	    if (extid == dvb_encodings[i].ext){
		conv = this->dvbconv[dvb_encodings[i].idx];
		s += 2;
		ls -= 2;
		break;
	    }
	}

	break;
    }
    default:{
	int enc = src[0];
	if (enc > 0 && enc < this->dvbconv_count){
	    conv = this->dvbconv[enc];
	    s += 1;
	    ls -= 1;
	} else {
	    conv = this->dvbconv[DVB_STR_ENC_DEFAULT];
	}
    }
    }

    if (conv == (iconv_t)-1){
	convert_dvb_string_fallback(src, src_len, dst, dst_len);
	return;
    }

    r = iconv(conv, &s, &ls, &d, &ld);

    if (r == (size_t)-1){
	if (errno == EILSEQ){
	    /* invalid multibyte sequence is encountered in the input */
	    /* use original string */
	    len = ld<ls ? ld:ls;
	    memcpy(d, s, len);
	    for (i=0; i<len; i++)
		if (!isprint(d[i]))
		    d[i] = '.';
	}

	if (errno == EINVAL){
	    /* An incomplete multibyte sequence is encountered in the input */
	    /* use original string */
	    len = ld<ls ? ld:ls;
	    memcpy(d, s, len);
	    for (i=0; i<len; i++)
		if (!isprint(d[i]))
		    d[i] = '.';
	}

	if (errno == E2BIG){
	    /* The output buffer has no more room for the next converted character */
	    /* just in cast.... */
	    dst[dst_len-1] = 0; /* fixme: use ld? */
	}	
    }

    /* add null character */
    if (d < (dst+dst_len))
	d[0] = 0;

}

#else /* ! HAVE_ICONV */

int csconv_init()
{
    return 0;
}

void csconv_cleanup()
{
    /* do nothing */
}

void convert_dvb_string(char *src, int src_len, char *dst, int dst_len)
{
    convert_dvb_string_fallback(src, src_len, dst, dst_len);
}

#endif /* HAVE_ICONV */
