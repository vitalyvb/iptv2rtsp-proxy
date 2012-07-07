
#line 1 "ebb_request_parser.rl"
/* This file is part of the libebb web server library
 *
 * Copyright (c) 2008 Ryan Dahl (ry@ndahl.us)
 * All rights reserved.
 *
 * This parser is based on code from Zed Shaw's Mongrel.
 * Copyright (c) 2005 Zed A. Shaw
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
 */
#include "ebb_request_parser.h"

#include <stdio.h>
#include <assert.h>

static const int unhex[] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
                     ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
                     ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
                     , 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1
                     ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
                     ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
                     ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
                     ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
                     };
#define TRUE 1
#define FALSE 0
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define REMAINING ((size_t)(pe - p))
#define CURRENT (parser->current_request)
#define CONTENT_LENGTH (parser->current_request->content_length)
#define CALLBACK(FOR)                               \
  if(CURRENT && parser->FOR##_mark && CURRENT->on_##FOR) {     \
    CURRENT->on_##FOR( CURRENT                      \
                , parser->FOR##_mark                \
                , p - parser->FOR##_mark            \
                );                                  \
 }
#define HEADER_CALLBACK(FOR)                        \
  if(CURRENT && parser->FOR##_mark && CURRENT->on_##FOR) {     \
    CURRENT->on_##FOR( CURRENT                      \
                , parser->FOR##_mark                \
                , p - parser->FOR##_mark            \
                , CURRENT->number_of_headers        \
                );                                  \
 }
#define END_REQUEST                        \
    if(CURRENT && CURRENT->on_complete)               \
      CURRENT->on_complete(CURRENT);       \
    CURRENT = NULL;



#line 309 "ebb_request_parser.rl"



#line 78 "ebb_request_parser.c"
static const int ebb_request_parser_start = 252;
static const int ebb_request_parser_first_final = 252;
static const int ebb_request_parser_error = 0;

static const int ebb_request_parser_en_ChunkedBody = 234;
static const int ebb_request_parser_en_ChunkedBody_chunk_chunk_end = 244;
static const int ebb_request_parser_en_main = 252;


#line 312 "ebb_request_parser.rl"

static void
skip_body(const char **p, ebb_request_parser *parser, size_t nskip) {
  if(CURRENT && CURRENT->on_body && nskip > 0) {
    CURRENT->on_body(CURRENT, *p, nskip);
  }
  if(CURRENT) CURRENT->body_read += nskip;
  parser->chunk_size -= nskip;
  *p += nskip;
  if(0 == parser->chunk_size) {
    parser->eating = FALSE;
    if(CURRENT && CURRENT->transfer_encoding == EBB_IDENTITY) {
      END_REQUEST;
    }
  } else {
    parser->eating = TRUE;
  }
}

void ebb_request_parser_init(ebb_request_parser *parser) 
{
  int cs = 0;
  
#line 112 "ebb_request_parser.c"
	{
	cs = ebb_request_parser_start;
	}

#line 335 "ebb_request_parser.rl"
  parser->cs = cs;

  parser->chunk_size = 0;
  parser->eating = 0;
  
  parser->current_request = NULL;

  parser->header_field_mark = parser->header_value_mark   = 
  parser->query_string_mark = parser->path_mark           = 
  parser->uri_mark          = parser->fragment_mark       = NULL;

  parser->new_request = NULL;
}


/** exec **/
size_t ebb_request_parser_execute(ebb_request_parser *parser, const char *buffer, size_t len)
{
  const char *p, *pe;
  int cs = parser->cs;

  assert(parser->new_request && "undefined callback");

  p = buffer;
  pe = buffer+len;

  if(0 < parser->chunk_size && parser->eating) {
    /* eat body */
    size_t eat = MIN(len, parser->chunk_size);
    skip_body(&p, parser, eat);
  } 

  if(parser->header_field_mark)   parser->header_field_mark   = buffer;
  if(parser->header_value_mark)   parser->header_value_mark   = buffer;
  if(parser->fragment_mark)       parser->fragment_mark       = buffer;
  if(parser->query_string_mark)   parser->query_string_mark   = buffer;
  if(parser->path_mark)           parser->path_mark           = buffer;
  if(parser->uri_mark)            parser->uri_mark            = buffer;

  
#line 158 "ebb_request_parser.c"
	{
	if ( p == pe )
		goto _test_eof;
	goto _resume;

_again:
	switch ( cs ) {
		case 252: goto st252;
		case 0: goto st0;
		case 1: goto st1;
		case 2: goto st2;
		case 3: goto st3;
		case 4: goto st4;
		case 5: goto st5;
		case 6: goto st6;
		case 7: goto st7;
		case 8: goto st8;
		case 9: goto st9;
		case 10: goto st10;
		case 11: goto st11;
		case 12: goto st12;
		case 13: goto st13;
		case 14: goto st14;
		case 15: goto st15;
		case 16: goto st16;
		case 17: goto st17;
		case 18: goto st18;
		case 19: goto st19;
		case 20: goto st20;
		case 21: goto st21;
		case 22: goto st22;
		case 23: goto st23;
		case 24: goto st24;
		case 25: goto st25;
		case 26: goto st26;
		case 27: goto st27;
		case 28: goto st28;
		case 29: goto st29;
		case 30: goto st30;
		case 31: goto st31;
		case 32: goto st32;
		case 33: goto st33;
		case 34: goto st34;
		case 35: goto st35;
		case 36: goto st36;
		case 37: goto st37;
		case 38: goto st38;
		case 39: goto st39;
		case 40: goto st40;
		case 41: goto st41;
		case 42: goto st42;
		case 43: goto st43;
		case 44: goto st44;
		case 45: goto st45;
		case 46: goto st46;
		case 47: goto st47;
		case 48: goto st48;
		case 49: goto st49;
		case 50: goto st50;
		case 51: goto st51;
		case 52: goto st52;
		case 53: goto st53;
		case 54: goto st54;
		case 55: goto st55;
		case 56: goto st56;
		case 57: goto st57;
		case 58: goto st58;
		case 59: goto st59;
		case 60: goto st60;
		case 61: goto st61;
		case 62: goto st62;
		case 63: goto st63;
		case 64: goto st64;
		case 65: goto st65;
		case 66: goto st66;
		case 67: goto st67;
		case 68: goto st68;
		case 69: goto st69;
		case 70: goto st70;
		case 71: goto st71;
		case 72: goto st72;
		case 73: goto st73;
		case 74: goto st74;
		case 75: goto st75;
		case 76: goto st76;
		case 77: goto st77;
		case 78: goto st78;
		case 79: goto st79;
		case 80: goto st80;
		case 81: goto st81;
		case 82: goto st82;
		case 83: goto st83;
		case 84: goto st84;
		case 85: goto st85;
		case 86: goto st86;
		case 87: goto st87;
		case 88: goto st88;
		case 89: goto st89;
		case 90: goto st90;
		case 91: goto st91;
		case 92: goto st92;
		case 93: goto st93;
		case 94: goto st94;
		case 95: goto st95;
		case 96: goto st96;
		case 97: goto st97;
		case 98: goto st98;
		case 99: goto st99;
		case 100: goto st100;
		case 101: goto st101;
		case 102: goto st102;
		case 103: goto st103;
		case 104: goto st104;
		case 105: goto st105;
		case 106: goto st106;
		case 107: goto st107;
		case 108: goto st108;
		case 109: goto st109;
		case 110: goto st110;
		case 111: goto st111;
		case 112: goto st112;
		case 113: goto st113;
		case 114: goto st114;
		case 115: goto st115;
		case 116: goto st116;
		case 117: goto st117;
		case 118: goto st118;
		case 119: goto st119;
		case 120: goto st120;
		case 121: goto st121;
		case 122: goto st122;
		case 123: goto st123;
		case 124: goto st124;
		case 125: goto st125;
		case 126: goto st126;
		case 127: goto st127;
		case 128: goto st128;
		case 129: goto st129;
		case 130: goto st130;
		case 131: goto st131;
		case 132: goto st132;
		case 133: goto st133;
		case 134: goto st134;
		case 135: goto st135;
		case 136: goto st136;
		case 137: goto st137;
		case 138: goto st138;
		case 139: goto st139;
		case 140: goto st140;
		case 141: goto st141;
		case 142: goto st142;
		case 143: goto st143;
		case 144: goto st144;
		case 145: goto st145;
		case 146: goto st146;
		case 147: goto st147;
		case 148: goto st148;
		case 149: goto st149;
		case 150: goto st150;
		case 151: goto st151;
		case 152: goto st152;
		case 153: goto st153;
		case 154: goto st154;
		case 155: goto st155;
		case 156: goto st156;
		case 157: goto st157;
		case 158: goto st158;
		case 159: goto st159;
		case 160: goto st160;
		case 161: goto st161;
		case 162: goto st162;
		case 163: goto st163;
		case 164: goto st164;
		case 165: goto st165;
		case 166: goto st166;
		case 167: goto st167;
		case 168: goto st168;
		case 169: goto st169;
		case 170: goto st170;
		case 171: goto st171;
		case 172: goto st172;
		case 173: goto st173;
		case 174: goto st174;
		case 175: goto st175;
		case 176: goto st176;
		case 177: goto st177;
		case 178: goto st178;
		case 179: goto st179;
		case 180: goto st180;
		case 181: goto st181;
		case 182: goto st182;
		case 183: goto st183;
		case 184: goto st184;
		case 185: goto st185;
		case 186: goto st186;
		case 187: goto st187;
		case 188: goto st188;
		case 189: goto st189;
		case 190: goto st190;
		case 191: goto st191;
		case 192: goto st192;
		case 193: goto st193;
		case 194: goto st194;
		case 195: goto st195;
		case 196: goto st196;
		case 197: goto st197;
		case 198: goto st198;
		case 199: goto st199;
		case 200: goto st200;
		case 201: goto st201;
		case 202: goto st202;
		case 203: goto st203;
		case 204: goto st204;
		case 205: goto st205;
		case 206: goto st206;
		case 207: goto st207;
		case 208: goto st208;
		case 209: goto st209;
		case 210: goto st210;
		case 211: goto st211;
		case 212: goto st212;
		case 213: goto st213;
		case 214: goto st214;
		case 215: goto st215;
		case 216: goto st216;
		case 217: goto st217;
		case 218: goto st218;
		case 219: goto st219;
		case 220: goto st220;
		case 221: goto st221;
		case 222: goto st222;
		case 223: goto st223;
		case 224: goto st224;
		case 225: goto st225;
		case 226: goto st226;
		case 227: goto st227;
		case 228: goto st228;
		case 229: goto st229;
		case 230: goto st230;
		case 231: goto st231;
		case 232: goto st232;
		case 233: goto st233;
		case 234: goto st234;
		case 235: goto st235;
		case 236: goto st236;
		case 237: goto st237;
		case 238: goto st238;
		case 253: goto st253;
		case 239: goto st239;
		case 240: goto st240;
		case 241: goto st241;
		case 242: goto st242;
		case 243: goto st243;
		case 244: goto st244;
		case 245: goto st245;
		case 246: goto st246;
		case 247: goto st247;
		case 248: goto st248;
		case 249: goto st249;
		case 250: goto st250;
		case 251: goto st251;
	default: break;
	}

	if ( ++p == pe )
		goto _test_eof;
_resume:
	switch ( cs )
	{
tr30:
	cs = 252;
#line 149 "ebb_request_parser.rl"
	{
    if(CURRENT && CURRENT->on_headers_complete)
      CURRENT->on_headers_complete(CURRENT);
  }
#line 179 "ebb_request_parser.rl"
	{
    if(CURRENT) { 
      if(CURRENT->transfer_encoding == EBB_CHUNKED) {
        cs = 234;
      } else {
        /* this is pretty stupid. i'd prefer to combine this with skip_chunk_data */
        parser->chunk_size = CURRENT->content_length;
        p += 1;  
        skip_body(&p, parser, MIN(REMAINING, CURRENT->content_length));
        p--;
        if(parser->chunk_size > REMAINING) {
          {p++; goto _out;}
        } 
      }
    }
  }
	goto _again;
st252:
	if ( ++p == pe )
		goto _test_eof252;
case 252:
#line 457 "ebb_request_parser.c"
	switch( (*p) ) {
		case 65: goto tr295;
		case 67: goto tr296;
		case 68: goto tr297;
		case 71: goto tr298;
		case 72: goto tr299;
		case 76: goto tr300;
		case 77: goto tr301;
		case 79: goto tr302;
		case 80: goto tr303;
		case 82: goto tr304;
		case 83: goto tr305;
		case 84: goto tr306;
		case 85: goto tr307;
	}
	goto st0;
st0:
cs = 0;
	goto _out;
tr295:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st1;
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
#line 488 "ebb_request_parser.c"
	if ( (*p) == 78 )
		goto st2;
	goto st0;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 78 )
		goto st3;
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( (*p) == 79 )
		goto st4;
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	if ( (*p) == 85 )
		goto st5;
	goto st0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( (*p) == 78 )
		goto st6;
	goto st0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	if ( (*p) == 67 )
		goto st7;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 69 )
		goto st8;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) == 32 )
		goto tr8;
	goto st0;
tr8:
#line 243 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_ANNOUNCE;  }
	goto st9;
tr146:
#line 228 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_COPY;      }
	goto st9;
tr153:
#line 229 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_DELETE;    }
	goto st9;
tr159:
#line 242 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_DESCRIBE;  }
	goto st9;
tr162:
#line 230 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_GET;       }
	goto st9;
tr173:
#line 244 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_GET_PARAMETER;    }
	goto st9;
tr177:
#line 231 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_HEAD;      }
	goto st9;
tr181:
#line 232 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_LOCK;      }
	goto st9;
tr187:
#line 233 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_MKCOL;     }
	goto st9;
tr190:
#line 234 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_MOVE;      }
	goto st9;
tr197:
#line 235 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_OPTIONS;   }
	goto st9;
tr206:
#line 245 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_PAUSE;     }
	goto st9;
tr209:
#line 246 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_PLAY;      }
	goto st9;
tr212:
#line 236 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_POST;      }
	goto st9;
tr220:
#line 237 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_PROPFIND;  }
	goto st9;
tr225:
#line 238 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_PROPPATCH; }
	goto st9;
tr227:
#line 239 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_PUT;       }
	goto st9;
tr234:
#line 247 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_RECORD;    }
	goto st9;
tr240:
#line 248 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_REDIRECT;  }
	goto st9;
tr246:
#line 249 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_SETUP;     }
	goto st9;
tr256:
#line 250 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_SET_PARAMETER;    }
	goto st9;
tr265:
#line 251 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_TEARDOWN;  }
	goto st9;
tr269:
#line 240 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_TRACE;     }
	goto st9;
tr275:
#line 241 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->method = EBB_UNLOCK;    }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 641 "ebb_request_parser.c"
	switch( (*p) ) {
		case 42: goto tr9;
		case 43: goto tr10;
		case 47: goto tr11;
		case 58: goto tr12;
	}
	if ( (*p) < 65 ) {
		if ( 45 <= (*p) && (*p) <= 57 )
			goto tr10;
	} else if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr10;
	} else
		goto tr10;
	goto st0;
tr9:
#line 78 "ebb_request_parser.rl"
	{ parser->uri_mark            = p; }
	goto st10;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
#line 665 "ebb_request_parser.c"
	switch( (*p) ) {
		case 32: goto tr13;
		case 35: goto tr14;
	}
	goto st0;
tr13:
#line 90 "ebb_request_parser.rl"
	{ 
    CALLBACK(uri);
    parser->uri_mark = NULL;
  }
	goto st11;
tr118:
#line 75 "ebb_request_parser.rl"
	{ parser->fragment_mark       = p; }
#line 95 "ebb_request_parser.rl"
	{ 
    CALLBACK(fragment);
    parser->fragment_mark = NULL;
  }
	goto st11;
tr121:
#line 95 "ebb_request_parser.rl"
	{ 
    CALLBACK(fragment);
    parser->fragment_mark = NULL;
  }
	goto st11;
tr129:
#line 105 "ebb_request_parser.rl"
	{
    CALLBACK(path);
    parser->path_mark = NULL;
  }
#line 90 "ebb_request_parser.rl"
	{ 
    CALLBACK(uri);
    parser->uri_mark = NULL;
  }
	goto st11;
tr135:
#line 76 "ebb_request_parser.rl"
	{ parser->query_string_mark   = p; }
#line 100 "ebb_request_parser.rl"
	{ 
    CALLBACK(query_string);
    parser->query_string_mark = NULL;
  }
#line 90 "ebb_request_parser.rl"
	{ 
    CALLBACK(uri);
    parser->uri_mark = NULL;
  }
	goto st11;
tr139:
#line 100 "ebb_request_parser.rl"
	{ 
    CALLBACK(query_string);
    parser->query_string_mark = NULL;
  }
#line 90 "ebb_request_parser.rl"
	{ 
    CALLBACK(uri);
    parser->uri_mark = NULL;
  }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 736 "ebb_request_parser.c"
	switch( (*p) ) {
		case 72: goto st12;
		case 82: goto st93;
	}
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	if ( (*p) == 84 )
		goto st13;
	goto st0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	if ( (*p) == 84 )
		goto st14;
	goto st0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	if ( (*p) == 80 )
		goto st15;
	goto st0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	if ( (*p) == 47 )
		goto tr20;
	goto st0;
tr20:
#line 254 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->protocol = EBB_PROTOCOL_HTTP;     }
	goto st16;
tr116:
#line 255 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->protocol = EBB_PROTOCOL_RTSP;     }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 782 "ebb_request_parser.c"
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr21;
	goto st0;
tr21:
#line 131 "ebb_request_parser.rl"
	{
    if(CURRENT) {
      CURRENT->version_major *= 10;
      CURRENT->version_major += *p - '0';
    }
  }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 799 "ebb_request_parser.c"
	if ( (*p) == 46 )
		goto st18;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr21;
	goto st0;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr23;
	goto st0;
tr23:
#line 138 "ebb_request_parser.rl"
	{
  	if(CURRENT) {
      CURRENT->version_minor *= 10;
      CURRENT->version_minor += *p - '0';
    }
  }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 825 "ebb_request_parser.c"
	if ( (*p) == 13 )
		goto st20;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr23;
	goto st0;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
	if ( (*p) == 10 )
		goto st21;
	goto st0;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
	switch( (*p) ) {
		case 13: goto st22;
		case 33: goto tr27;
		case 67: goto tr28;
		case 84: goto tr29;
		case 99: goto tr28;
		case 116: goto tr29;
		case 124: goto tr27;
		case 126: goto tr27;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr27;
		} else if ( (*p) >= 35 )
			goto tr27;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto tr27;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto tr27;
		} else
			goto tr27;
	} else
		goto tr27;
	goto st0;
tr39:
#line 145 "ebb_request_parser.rl"
	{
    if(CURRENT) CURRENT->number_of_headers++;
  }
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 880 "ebb_request_parser.c"
	if ( (*p) == 10 )
		goto tr30;
	goto st0;
tr27:
#line 73 "ebb_request_parser.rl"
	{ parser->header_field_mark   = p; }
	goto st23;
tr40:
#line 145 "ebb_request_parser.rl"
	{
    if(CURRENT) CURRENT->number_of_headers++;
  }
#line 73 "ebb_request_parser.rl"
	{ parser->header_field_mark   = p; }
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 900 "ebb_request_parser.c"
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
tr32:
#line 80 "ebb_request_parser.rl"
	{ 
    HEADER_CALLBACK(header_field);
    parser->header_field_mark = NULL;
  }
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 936 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto tr34;
		case 32: goto st24;
	}
	goto tr33;
tr33:
#line 74 "ebb_request_parser.rl"
	{ parser->header_value_mark   = p; }
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 950 "ebb_request_parser.c"
	if ( (*p) == 13 )
		goto tr37;
	goto st25;
tr34:
#line 74 "ebb_request_parser.rl"
	{ parser->header_value_mark   = p; }
#line 85 "ebb_request_parser.rl"
	{
    HEADER_CALLBACK(header_value);
    parser->header_value_mark = NULL;
  }
	goto st26;
tr37:
#line 85 "ebb_request_parser.rl"
	{
    HEADER_CALLBACK(header_value);
    parser->header_value_mark = NULL;
  }
	goto st26;
tr61:
#line 121 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->keep_alive = FALSE; }
#line 85 "ebb_request_parser.rl"
	{
    HEADER_CALLBACK(header_value);
    parser->header_value_mark = NULL;
  }
	goto st26;
tr71:
#line 120 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->keep_alive = TRUE; }
#line 85 "ebb_request_parser.rl"
	{
    HEADER_CALLBACK(header_value);
    parser->header_value_mark = NULL;
  }
	goto st26;
tr112:
#line 117 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->transfer_encoding = EBB_IDENTITY; }
#line 85 "ebb_request_parser.rl"
	{
    HEADER_CALLBACK(header_value);
    parser->header_value_mark = NULL;
  }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 1001 "ebb_request_parser.c"
	if ( (*p) == 10 )
		goto st27;
	goto st0;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
	switch( (*p) ) {
		case 13: goto tr39;
		case 33: goto tr40;
		case 67: goto tr41;
		case 84: goto tr42;
		case 99: goto tr41;
		case 116: goto tr42;
		case 124: goto tr40;
		case 126: goto tr40;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto tr40;
		} else if ( (*p) >= 35 )
			goto tr40;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto tr40;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto tr40;
		} else
			goto tr40;
	} else
		goto tr40;
	goto st0;
tr28:
#line 73 "ebb_request_parser.rl"
	{ parser->header_field_mark   = p; }
	goto st28;
tr41:
#line 145 "ebb_request_parser.rl"
	{
    if(CURRENT) CURRENT->number_of_headers++;
  }
#line 73 "ebb_request_parser.rl"
	{ parser->header_field_mark   = p; }
	goto st28;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
#line 1053 "ebb_request_parser.c"
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 79: goto st29;
		case 111: goto st29;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 78: goto st30;
		case 110: goto st30;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 78: goto st31;
		case 84: goto st54;
		case 110: goto st31;
		case 116: goto st54;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 69: goto st32;
		case 101: goto st32;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 67: goto st33;
		case 99: goto st33;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 84: goto st34;
		case 116: goto st34;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 73: goto st35;
		case 105: goto st35;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 79: goto st36;
		case 111: goto st36;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 78: goto st37;
		case 110: goto st37;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr53;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
tr53:
#line 80 "ebb_request_parser.rl"
	{ 
    HEADER_CALLBACK(header_field);
    parser->header_field_mark = NULL;
  }
	goto st38;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
#line 1361 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto tr34;
		case 32: goto st38;
		case 67: goto tr55;
		case 75: goto tr56;
		case 99: goto tr55;
		case 107: goto tr56;
	}
	goto tr33;
tr55:
#line 74 "ebb_request_parser.rl"
	{ parser->header_value_mark   = p; }
	goto st39;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
#line 1379 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto tr37;
		case 76: goto st40;
		case 108: goto st40;
	}
	goto st25;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
	switch( (*p) ) {
		case 13: goto tr37;
		case 79: goto st41;
		case 111: goto st41;
	}
	goto st25;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
	switch( (*p) ) {
		case 13: goto tr37;
		case 83: goto st42;
		case 115: goto st42;
	}
	goto st25;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
	switch( (*p) ) {
		case 13: goto tr37;
		case 69: goto st43;
		case 101: goto st43;
	}
	goto st25;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
	if ( (*p) == 13 )
		goto tr61;
	goto st25;
tr56:
#line 74 "ebb_request_parser.rl"
	{ parser->header_value_mark   = p; }
	goto st44;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
#line 1431 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto tr37;
		case 69: goto st45;
		case 101: goto st45;
	}
	goto st25;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
	switch( (*p) ) {
		case 13: goto tr37;
		case 69: goto st46;
		case 101: goto st46;
	}
	goto st25;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
	switch( (*p) ) {
		case 13: goto tr37;
		case 80: goto st47;
		case 112: goto st47;
	}
	goto st25;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
	switch( (*p) ) {
		case 13: goto tr37;
		case 45: goto st48;
	}
	goto st25;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
	switch( (*p) ) {
		case 13: goto tr37;
		case 65: goto st49;
		case 97: goto st49;
	}
	goto st25;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
	switch( (*p) ) {
		case 13: goto tr37;
		case 76: goto st50;
		case 108: goto st50;
	}
	goto st25;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
	switch( (*p) ) {
		case 13: goto tr37;
		case 73: goto st51;
		case 105: goto st51;
	}
	goto st25;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
	switch( (*p) ) {
		case 13: goto tr37;
		case 86: goto st52;
		case 118: goto st52;
	}
	goto st25;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
	switch( (*p) ) {
		case 13: goto tr37;
		case 69: goto st53;
		case 101: goto st53;
	}
	goto st25;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
	if ( (*p) == 13 )
		goto tr71;
	goto st25;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 69: goto st55;
		case 101: goto st55;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 78: goto st56;
		case 110: goto st56;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 84: goto st57;
		case 116: goto st57;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
	switch( (*p) ) {
		case 33: goto st23;
		case 45: goto st58;
		case 46: goto st23;
		case 58: goto tr32;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 48 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else if ( (*p) >= 65 )
			goto st23;
	} else
		goto st23;
	goto st0;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 76: goto st59;
		case 108: goto st59;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 69: goto st60;
		case 101: goto st60;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 78: goto st61;
		case 110: goto st61;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 71: goto st62;
		case 103: goto st62;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 84: goto st63;
		case 116: goto st63;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 72: goto st64;
		case 104: goto st64;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr82;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
tr82:
#line 80 "ebb_request_parser.rl"
	{ 
    HEADER_CALLBACK(header_field);
    parser->header_field_mark = NULL;
  }
	goto st65;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
#line 1860 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto tr34;
		case 32: goto st65;
	}
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr84;
	goto tr33;
tr84:
#line 110 "ebb_request_parser.rl"
	{
    if(CURRENT){
      CURRENT->content_length *= 10;
      CURRENT->content_length += *p - '0';
    }
  }
#line 74 "ebb_request_parser.rl"
	{ parser->header_value_mark   = p; }
	goto st66;
tr85:
#line 110 "ebb_request_parser.rl"
	{
    if(CURRENT){
      CURRENT->content_length *= 10;
      CURRENT->content_length += *p - '0';
    }
  }
	goto st66;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
#line 1892 "ebb_request_parser.c"
	if ( (*p) == 13 )
		goto tr37;
	if ( 48 <= (*p) && (*p) <= 57 )
		goto tr85;
	goto st25;
tr29:
#line 73 "ebb_request_parser.rl"
	{ parser->header_field_mark   = p; }
	goto st67;
tr42:
#line 145 "ebb_request_parser.rl"
	{
    if(CURRENT) CURRENT->number_of_headers++;
  }
#line 73 "ebb_request_parser.rl"
	{ parser->header_field_mark   = p; }
	goto st67;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
#line 1914 "ebb_request_parser.c"
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 82: goto st68;
		case 114: goto st68;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 65: goto st69;
		case 97: goto st69;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 66 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 78: goto st70;
		case 110: goto st70;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 83: goto st71;
		case 115: goto st71;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 70: goto st72;
		case 102: goto st72;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 69: goto st73;
		case 101: goto st73;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st73:
	if ( ++p == pe )
		goto _test_eof73;
case 73:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 82: goto st74;
		case 114: goto st74;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st74:
	if ( ++p == pe )
		goto _test_eof74;
case 74:
	switch( (*p) ) {
		case 33: goto st23;
		case 45: goto st75;
		case 46: goto st23;
		case 58: goto tr32;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 48 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else if ( (*p) >= 65 )
			goto st23;
	} else
		goto st23;
	goto st0;
st75:
	if ( ++p == pe )
		goto _test_eof75;
case 75:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 69: goto st76;
		case 101: goto st76;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st76:
	if ( ++p == pe )
		goto _test_eof76;
case 76:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 78: goto st77;
		case 110: goto st77;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st77:
	if ( ++p == pe )
		goto _test_eof77;
case 77:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 67: goto st78;
		case 99: goto st78;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st78:
	if ( ++p == pe )
		goto _test_eof78;
case 78:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 79: goto st79;
		case 111: goto st79;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st79:
	if ( ++p == pe )
		goto _test_eof79;
case 79:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 68: goto st80;
		case 100: goto st80;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st80:
	if ( ++p == pe )
		goto _test_eof80;
case 80:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 73: goto st81;
		case 105: goto st81;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st81:
	if ( ++p == pe )
		goto _test_eof81;
case 81:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 78: goto st82;
		case 110: goto st82;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st82:
	if ( ++p == pe )
		goto _test_eof82;
case 82:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr32;
		case 71: goto st83;
		case 103: goto st83;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
st83:
	if ( ++p == pe )
		goto _test_eof83;
case 83:
	switch( (*p) ) {
		case 33: goto st23;
		case 58: goto tr102;
		case 124: goto st23;
		case 126: goto st23;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st23;
		} else if ( (*p) >= 35 )
			goto st23;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st23;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st23;
		} else
			goto st23;
	} else
		goto st23;
	goto st0;
tr102:
#line 118 "ebb_request_parser.rl"
	{ if(CURRENT) CURRENT->transfer_encoding = EBB_CHUNKED; }
#line 80 "ebb_request_parser.rl"
	{ 
    HEADER_CALLBACK(header_field);
    parser->header_field_mark = NULL;
  }
	goto st84;
st84:
	if ( ++p == pe )
		goto _test_eof84;
case 84:
#line 2429 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto tr34;
		case 32: goto st84;
		case 105: goto tr104;
	}
	goto tr33;
tr104:
#line 74 "ebb_request_parser.rl"
	{ parser->header_value_mark   = p; }
	goto st85;
st85:
	if ( ++p == pe )
		goto _test_eof85;
case 85:
#line 2444 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto tr37;
		case 100: goto st86;
	}
	goto st25;
st86:
	if ( ++p == pe )
		goto _test_eof86;
case 86:
	switch( (*p) ) {
		case 13: goto tr37;
		case 101: goto st87;
	}
	goto st25;
st87:
	if ( ++p == pe )
		goto _test_eof87;
case 87:
	switch( (*p) ) {
		case 13: goto tr37;
		case 110: goto st88;
	}
	goto st25;
st88:
	if ( ++p == pe )
		goto _test_eof88;
case 88:
	switch( (*p) ) {
		case 13: goto tr37;
		case 116: goto st89;
	}
	goto st25;
st89:
	if ( ++p == pe )
		goto _test_eof89;
case 89:
	switch( (*p) ) {
		case 13: goto tr37;
		case 105: goto st90;
	}
	goto st25;
st90:
	if ( ++p == pe )
		goto _test_eof90;
case 90:
	switch( (*p) ) {
		case 13: goto tr37;
		case 116: goto st91;
	}
	goto st25;
st91:
	if ( ++p == pe )
		goto _test_eof91;
case 91:
	switch( (*p) ) {
		case 13: goto tr37;
		case 121: goto st92;
	}
	goto st25;
st92:
	if ( ++p == pe )
		goto _test_eof92;
case 92:
	if ( (*p) == 13 )
		goto tr112;
	goto st25;
st93:
	if ( ++p == pe )
		goto _test_eof93;
case 93:
	if ( (*p) == 84 )
		goto st94;
	goto st0;
st94:
	if ( ++p == pe )
		goto _test_eof94;
case 94:
	if ( (*p) == 83 )
		goto st95;
	goto st0;
st95:
	if ( ++p == pe )
		goto _test_eof95;
case 95:
	if ( (*p) == 80 )
		goto st96;
	goto st0;
st96:
	if ( ++p == pe )
		goto _test_eof96;
case 96:
	if ( (*p) == 47 )
		goto tr116;
	goto st0;
tr14:
#line 90 "ebb_request_parser.rl"
	{ 
    CALLBACK(uri);
    parser->uri_mark = NULL;
  }
	goto st97;
tr130:
#line 105 "ebb_request_parser.rl"
	{
    CALLBACK(path);
    parser->path_mark = NULL;
  }
#line 90 "ebb_request_parser.rl"
	{ 
    CALLBACK(uri);
    parser->uri_mark = NULL;
  }
	goto st97;
tr136:
#line 76 "ebb_request_parser.rl"
	{ parser->query_string_mark   = p; }
#line 100 "ebb_request_parser.rl"
	{ 
    CALLBACK(query_string);
    parser->query_string_mark = NULL;
  }
#line 90 "ebb_request_parser.rl"
	{ 
    CALLBACK(uri);
    parser->uri_mark = NULL;
  }
	goto st97;
tr140:
#line 100 "ebb_request_parser.rl"
	{ 
    CALLBACK(query_string);
    parser->query_string_mark = NULL;
  }
#line 90 "ebb_request_parser.rl"
	{ 
    CALLBACK(uri);
    parser->uri_mark = NULL;
  }
	goto st97;
st97:
	if ( ++p == pe )
		goto _test_eof97;
case 97:
#line 2588 "ebb_request_parser.c"
	switch( (*p) ) {
		case 32: goto tr118;
		case 37: goto tr119;
		case 60: goto st0;
		case 62: goto st0;
		case 127: goto st0;
	}
	if ( (*p) > 31 ) {
		if ( 34 <= (*p) && (*p) <= 35 )
			goto st0;
	} else if ( (*p) >= 0 )
		goto st0;
	goto tr117;
tr117:
#line 75 "ebb_request_parser.rl"
	{ parser->fragment_mark       = p; }
	goto st98;
st98:
	if ( ++p == pe )
		goto _test_eof98;
case 98:
#line 2610 "ebb_request_parser.c"
	switch( (*p) ) {
		case 32: goto tr121;
		case 37: goto st99;
		case 60: goto st0;
		case 62: goto st0;
		case 127: goto st0;
	}
	if ( (*p) > 31 ) {
		if ( 34 <= (*p) && (*p) <= 35 )
			goto st0;
	} else if ( (*p) >= 0 )
		goto st0;
	goto st98;
tr119:
#line 75 "ebb_request_parser.rl"
	{ parser->fragment_mark       = p; }
	goto st99;
st99:
	if ( ++p == pe )
		goto _test_eof99;
case 99:
#line 2632 "ebb_request_parser.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st100;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st100;
	} else
		goto st100;
	goto st0;
st100:
	if ( ++p == pe )
		goto _test_eof100;
case 100:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st98;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st98;
	} else
		goto st98;
	goto st0;
tr10:
#line 78 "ebb_request_parser.rl"
	{ parser->uri_mark            = p; }
	goto st101;
st101:
	if ( ++p == pe )
		goto _test_eof101;
case 101:
#line 2663 "ebb_request_parser.c"
	switch( (*p) ) {
		case 43: goto st101;
		case 58: goto st102;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto st101;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto st101;
		} else if ( (*p) >= 65 )
			goto st101;
	} else
		goto st101;
	goto st0;
tr12:
#line 78 "ebb_request_parser.rl"
	{ parser->uri_mark            = p; }
	goto st102;
st102:
	if ( ++p == pe )
		goto _test_eof102;
case 102:
#line 2688 "ebb_request_parser.c"
	switch( (*p) ) {
		case 32: goto tr13;
		case 34: goto st0;
		case 35: goto tr14;
		case 37: goto st103;
		case 60: goto st0;
		case 62: goto st0;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto st102;
st103:
	if ( ++p == pe )
		goto _test_eof103;
case 103:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st104;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st104;
	} else
		goto st104;
	goto st0;
st104:
	if ( ++p == pe )
		goto _test_eof104;
case 104:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st102;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st102;
	} else
		goto st102;
	goto st0;
tr11:
#line 78 "ebb_request_parser.rl"
	{ parser->uri_mark            = p; }
#line 77 "ebb_request_parser.rl"
	{ parser->path_mark           = p; }
	goto st105;
st105:
	if ( ++p == pe )
		goto _test_eof105;
case 105:
#line 2737 "ebb_request_parser.c"
	switch( (*p) ) {
		case 32: goto tr129;
		case 34: goto st0;
		case 35: goto tr130;
		case 37: goto st106;
		case 60: goto st0;
		case 62: goto st0;
		case 63: goto tr132;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto st105;
st106:
	if ( ++p == pe )
		goto _test_eof106;
case 106:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st107;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st107;
	} else
		goto st107;
	goto st0;
st107:
	if ( ++p == pe )
		goto _test_eof107;
case 107:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st105;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st105;
	} else
		goto st105;
	goto st0;
tr132:
#line 105 "ebb_request_parser.rl"
	{
    CALLBACK(path);
    parser->path_mark = NULL;
  }
	goto st108;
st108:
	if ( ++p == pe )
		goto _test_eof108;
case 108:
#line 2788 "ebb_request_parser.c"
	switch( (*p) ) {
		case 32: goto tr135;
		case 34: goto st0;
		case 35: goto tr136;
		case 37: goto tr137;
		case 60: goto st0;
		case 62: goto st0;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto tr134;
tr134:
#line 76 "ebb_request_parser.rl"
	{ parser->query_string_mark   = p; }
	goto st109;
st109:
	if ( ++p == pe )
		goto _test_eof109;
case 109:
#line 2809 "ebb_request_parser.c"
	switch( (*p) ) {
		case 32: goto tr139;
		case 34: goto st0;
		case 35: goto tr140;
		case 37: goto st110;
		case 60: goto st0;
		case 62: goto st0;
		case 127: goto st0;
	}
	if ( 0 <= (*p) && (*p) <= 31 )
		goto st0;
	goto st109;
tr137:
#line 76 "ebb_request_parser.rl"
	{ parser->query_string_mark   = p; }
	goto st110;
st110:
	if ( ++p == pe )
		goto _test_eof110;
case 110:
#line 2830 "ebb_request_parser.c"
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st111;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st111;
	} else
		goto st111;
	goto st0;
st111:
	if ( ++p == pe )
		goto _test_eof111;
case 111:
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto st109;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto st109;
	} else
		goto st109;
	goto st0;
tr296:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st112;
st112:
	if ( ++p == pe )
		goto _test_eof112;
case 112:
#line 2864 "ebb_request_parser.c"
	if ( (*p) == 79 )
		goto st113;
	goto st0;
st113:
	if ( ++p == pe )
		goto _test_eof113;
case 113:
	if ( (*p) == 80 )
		goto st114;
	goto st0;
st114:
	if ( ++p == pe )
		goto _test_eof114;
case 114:
	if ( (*p) == 89 )
		goto st115;
	goto st0;
st115:
	if ( ++p == pe )
		goto _test_eof115;
case 115:
	if ( (*p) == 32 )
		goto tr146;
	goto st0;
tr297:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st116;
st116:
	if ( ++p == pe )
		goto _test_eof116;
case 116:
#line 2900 "ebb_request_parser.c"
	if ( (*p) == 69 )
		goto st117;
	goto st0;
st117:
	if ( ++p == pe )
		goto _test_eof117;
case 117:
	switch( (*p) ) {
		case 76: goto st118;
		case 83: goto st122;
	}
	goto st0;
st118:
	if ( ++p == pe )
		goto _test_eof118;
case 118:
	if ( (*p) == 69 )
		goto st119;
	goto st0;
st119:
	if ( ++p == pe )
		goto _test_eof119;
case 119:
	if ( (*p) == 84 )
		goto st120;
	goto st0;
st120:
	if ( ++p == pe )
		goto _test_eof120;
case 120:
	if ( (*p) == 69 )
		goto st121;
	goto st0;
st121:
	if ( ++p == pe )
		goto _test_eof121;
case 121:
	if ( (*p) == 32 )
		goto tr153;
	goto st0;
st122:
	if ( ++p == pe )
		goto _test_eof122;
case 122:
	if ( (*p) == 67 )
		goto st123;
	goto st0;
st123:
	if ( ++p == pe )
		goto _test_eof123;
case 123:
	if ( (*p) == 82 )
		goto st124;
	goto st0;
st124:
	if ( ++p == pe )
		goto _test_eof124;
case 124:
	if ( (*p) == 73 )
		goto st125;
	goto st0;
st125:
	if ( ++p == pe )
		goto _test_eof125;
case 125:
	if ( (*p) == 66 )
		goto st126;
	goto st0;
st126:
	if ( ++p == pe )
		goto _test_eof126;
case 126:
	if ( (*p) == 69 )
		goto st127;
	goto st0;
st127:
	if ( ++p == pe )
		goto _test_eof127;
case 127:
	if ( (*p) == 32 )
		goto tr159;
	goto st0;
tr298:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st128;
st128:
	if ( ++p == pe )
		goto _test_eof128;
case 128:
#line 2994 "ebb_request_parser.c"
	if ( (*p) == 69 )
		goto st129;
	goto st0;
st129:
	if ( ++p == pe )
		goto _test_eof129;
case 129:
	if ( (*p) == 84 )
		goto st130;
	goto st0;
st130:
	if ( ++p == pe )
		goto _test_eof130;
case 130:
	switch( (*p) ) {
		case 32: goto tr162;
		case 95: goto st131;
	}
	goto st0;
st131:
	if ( ++p == pe )
		goto _test_eof131;
case 131:
	if ( (*p) == 80 )
		goto st132;
	goto st0;
st132:
	if ( ++p == pe )
		goto _test_eof132;
case 132:
	if ( (*p) == 65 )
		goto st133;
	goto st0;
st133:
	if ( ++p == pe )
		goto _test_eof133;
case 133:
	if ( (*p) == 82 )
		goto st134;
	goto st0;
st134:
	if ( ++p == pe )
		goto _test_eof134;
case 134:
	if ( (*p) == 65 )
		goto st135;
	goto st0;
st135:
	if ( ++p == pe )
		goto _test_eof135;
case 135:
	if ( (*p) == 77 )
		goto st136;
	goto st0;
st136:
	if ( ++p == pe )
		goto _test_eof136;
case 136:
	if ( (*p) == 69 )
		goto st137;
	goto st0;
st137:
	if ( ++p == pe )
		goto _test_eof137;
case 137:
	if ( (*p) == 84 )
		goto st138;
	goto st0;
st138:
	if ( ++p == pe )
		goto _test_eof138;
case 138:
	if ( (*p) == 69 )
		goto st139;
	goto st0;
st139:
	if ( ++p == pe )
		goto _test_eof139;
case 139:
	if ( (*p) == 82 )
		goto st140;
	goto st0;
st140:
	if ( ++p == pe )
		goto _test_eof140;
case 140:
	if ( (*p) == 32 )
		goto tr173;
	goto st0;
tr299:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st141;
st141:
	if ( ++p == pe )
		goto _test_eof141;
case 141:
#line 3095 "ebb_request_parser.c"
	if ( (*p) == 69 )
		goto st142;
	goto st0;
st142:
	if ( ++p == pe )
		goto _test_eof142;
case 142:
	if ( (*p) == 65 )
		goto st143;
	goto st0;
st143:
	if ( ++p == pe )
		goto _test_eof143;
case 143:
	if ( (*p) == 68 )
		goto st144;
	goto st0;
st144:
	if ( ++p == pe )
		goto _test_eof144;
case 144:
	if ( (*p) == 32 )
		goto tr177;
	goto st0;
tr300:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st145;
st145:
	if ( ++p == pe )
		goto _test_eof145;
case 145:
#line 3131 "ebb_request_parser.c"
	if ( (*p) == 79 )
		goto st146;
	goto st0;
st146:
	if ( ++p == pe )
		goto _test_eof146;
case 146:
	if ( (*p) == 67 )
		goto st147;
	goto st0;
st147:
	if ( ++p == pe )
		goto _test_eof147;
case 147:
	if ( (*p) == 75 )
		goto st148;
	goto st0;
st148:
	if ( ++p == pe )
		goto _test_eof148;
case 148:
	if ( (*p) == 32 )
		goto tr181;
	goto st0;
tr301:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st149;
st149:
	if ( ++p == pe )
		goto _test_eof149;
case 149:
#line 3167 "ebb_request_parser.c"
	switch( (*p) ) {
		case 75: goto st150;
		case 79: goto st154;
	}
	goto st0;
st150:
	if ( ++p == pe )
		goto _test_eof150;
case 150:
	if ( (*p) == 67 )
		goto st151;
	goto st0;
st151:
	if ( ++p == pe )
		goto _test_eof151;
case 151:
	if ( (*p) == 79 )
		goto st152;
	goto st0;
st152:
	if ( ++p == pe )
		goto _test_eof152;
case 152:
	if ( (*p) == 76 )
		goto st153;
	goto st0;
st153:
	if ( ++p == pe )
		goto _test_eof153;
case 153:
	if ( (*p) == 32 )
		goto tr187;
	goto st0;
st154:
	if ( ++p == pe )
		goto _test_eof154;
case 154:
	if ( (*p) == 86 )
		goto st155;
	goto st0;
st155:
	if ( ++p == pe )
		goto _test_eof155;
case 155:
	if ( (*p) == 69 )
		goto st156;
	goto st0;
st156:
	if ( ++p == pe )
		goto _test_eof156;
case 156:
	if ( (*p) == 32 )
		goto tr190;
	goto st0;
tr302:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st157;
st157:
	if ( ++p == pe )
		goto _test_eof157;
case 157:
#line 3233 "ebb_request_parser.c"
	if ( (*p) == 80 )
		goto st158;
	goto st0;
st158:
	if ( ++p == pe )
		goto _test_eof158;
case 158:
	if ( (*p) == 84 )
		goto st159;
	goto st0;
st159:
	if ( ++p == pe )
		goto _test_eof159;
case 159:
	if ( (*p) == 73 )
		goto st160;
	goto st0;
st160:
	if ( ++p == pe )
		goto _test_eof160;
case 160:
	if ( (*p) == 79 )
		goto st161;
	goto st0;
st161:
	if ( ++p == pe )
		goto _test_eof161;
case 161:
	if ( (*p) == 78 )
		goto st162;
	goto st0;
st162:
	if ( ++p == pe )
		goto _test_eof162;
case 162:
	if ( (*p) == 83 )
		goto st163;
	goto st0;
st163:
	if ( ++p == pe )
		goto _test_eof163;
case 163:
	if ( (*p) == 32 )
		goto tr197;
	goto st0;
tr303:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st164;
st164:
	if ( ++p == pe )
		goto _test_eof164;
case 164:
#line 3290 "ebb_request_parser.c"
	switch( (*p) ) {
		case 65: goto st165;
		case 76: goto st169;
		case 79: goto st172;
		case 82: goto st175;
		case 85: goto st187;
	}
	goto st0;
st165:
	if ( ++p == pe )
		goto _test_eof165;
case 165:
	if ( (*p) == 85 )
		goto st166;
	goto st0;
st166:
	if ( ++p == pe )
		goto _test_eof166;
case 166:
	if ( (*p) == 83 )
		goto st167;
	goto st0;
st167:
	if ( ++p == pe )
		goto _test_eof167;
case 167:
	if ( (*p) == 69 )
		goto st168;
	goto st0;
st168:
	if ( ++p == pe )
		goto _test_eof168;
case 168:
	if ( (*p) == 32 )
		goto tr206;
	goto st0;
st169:
	if ( ++p == pe )
		goto _test_eof169;
case 169:
	if ( (*p) == 65 )
		goto st170;
	goto st0;
st170:
	if ( ++p == pe )
		goto _test_eof170;
case 170:
	if ( (*p) == 89 )
		goto st171;
	goto st0;
st171:
	if ( ++p == pe )
		goto _test_eof171;
case 171:
	if ( (*p) == 32 )
		goto tr209;
	goto st0;
st172:
	if ( ++p == pe )
		goto _test_eof172;
case 172:
	if ( (*p) == 83 )
		goto st173;
	goto st0;
st173:
	if ( ++p == pe )
		goto _test_eof173;
case 173:
	if ( (*p) == 84 )
		goto st174;
	goto st0;
st174:
	if ( ++p == pe )
		goto _test_eof174;
case 174:
	if ( (*p) == 32 )
		goto tr212;
	goto st0;
st175:
	if ( ++p == pe )
		goto _test_eof175;
case 175:
	if ( (*p) == 79 )
		goto st176;
	goto st0;
st176:
	if ( ++p == pe )
		goto _test_eof176;
case 176:
	if ( (*p) == 80 )
		goto st177;
	goto st0;
st177:
	if ( ++p == pe )
		goto _test_eof177;
case 177:
	switch( (*p) ) {
		case 70: goto st178;
		case 80: goto st182;
	}
	goto st0;
st178:
	if ( ++p == pe )
		goto _test_eof178;
case 178:
	if ( (*p) == 73 )
		goto st179;
	goto st0;
st179:
	if ( ++p == pe )
		goto _test_eof179;
case 179:
	if ( (*p) == 78 )
		goto st180;
	goto st0;
st180:
	if ( ++p == pe )
		goto _test_eof180;
case 180:
	if ( (*p) == 68 )
		goto st181;
	goto st0;
st181:
	if ( ++p == pe )
		goto _test_eof181;
case 181:
	if ( (*p) == 32 )
		goto tr220;
	goto st0;
st182:
	if ( ++p == pe )
		goto _test_eof182;
case 182:
	if ( (*p) == 65 )
		goto st183;
	goto st0;
st183:
	if ( ++p == pe )
		goto _test_eof183;
case 183:
	if ( (*p) == 84 )
		goto st184;
	goto st0;
st184:
	if ( ++p == pe )
		goto _test_eof184;
case 184:
	if ( (*p) == 67 )
		goto st185;
	goto st0;
st185:
	if ( ++p == pe )
		goto _test_eof185;
case 185:
	if ( (*p) == 72 )
		goto st186;
	goto st0;
st186:
	if ( ++p == pe )
		goto _test_eof186;
case 186:
	if ( (*p) == 32 )
		goto tr225;
	goto st0;
st187:
	if ( ++p == pe )
		goto _test_eof187;
case 187:
	if ( (*p) == 84 )
		goto st188;
	goto st0;
st188:
	if ( ++p == pe )
		goto _test_eof188;
case 188:
	if ( (*p) == 32 )
		goto tr227;
	goto st0;
tr304:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st189;
st189:
	if ( ++p == pe )
		goto _test_eof189;
case 189:
#line 3480 "ebb_request_parser.c"
	if ( (*p) == 69 )
		goto st190;
	goto st0;
st190:
	if ( ++p == pe )
		goto _test_eof190;
case 190:
	switch( (*p) ) {
		case 67: goto st191;
		case 68: goto st195;
	}
	goto st0;
st191:
	if ( ++p == pe )
		goto _test_eof191;
case 191:
	if ( (*p) == 79 )
		goto st192;
	goto st0;
st192:
	if ( ++p == pe )
		goto _test_eof192;
case 192:
	if ( (*p) == 82 )
		goto st193;
	goto st0;
st193:
	if ( ++p == pe )
		goto _test_eof193;
case 193:
	if ( (*p) == 68 )
		goto st194;
	goto st0;
st194:
	if ( ++p == pe )
		goto _test_eof194;
case 194:
	if ( (*p) == 32 )
		goto tr234;
	goto st0;
st195:
	if ( ++p == pe )
		goto _test_eof195;
case 195:
	if ( (*p) == 73 )
		goto st196;
	goto st0;
st196:
	if ( ++p == pe )
		goto _test_eof196;
case 196:
	if ( (*p) == 82 )
		goto st197;
	goto st0;
st197:
	if ( ++p == pe )
		goto _test_eof197;
case 197:
	if ( (*p) == 69 )
		goto st198;
	goto st0;
st198:
	if ( ++p == pe )
		goto _test_eof198;
case 198:
	if ( (*p) == 67 )
		goto st199;
	goto st0;
st199:
	if ( ++p == pe )
		goto _test_eof199;
case 199:
	if ( (*p) == 84 )
		goto st200;
	goto st0;
st200:
	if ( ++p == pe )
		goto _test_eof200;
case 200:
	if ( (*p) == 32 )
		goto tr240;
	goto st0;
tr305:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st201;
st201:
	if ( ++p == pe )
		goto _test_eof201;
case 201:
#line 3574 "ebb_request_parser.c"
	if ( (*p) == 69 )
		goto st202;
	goto st0;
st202:
	if ( ++p == pe )
		goto _test_eof202;
case 202:
	if ( (*p) == 84 )
		goto st203;
	goto st0;
st203:
	if ( ++p == pe )
		goto _test_eof203;
case 203:
	switch( (*p) ) {
		case 85: goto st204;
		case 95: goto st206;
	}
	goto st0;
st204:
	if ( ++p == pe )
		goto _test_eof204;
case 204:
	if ( (*p) == 80 )
		goto st205;
	goto st0;
st205:
	if ( ++p == pe )
		goto _test_eof205;
case 205:
	if ( (*p) == 32 )
		goto tr246;
	goto st0;
st206:
	if ( ++p == pe )
		goto _test_eof206;
case 206:
	if ( (*p) == 80 )
		goto st207;
	goto st0;
st207:
	if ( ++p == pe )
		goto _test_eof207;
case 207:
	if ( (*p) == 65 )
		goto st208;
	goto st0;
st208:
	if ( ++p == pe )
		goto _test_eof208;
case 208:
	if ( (*p) == 82 )
		goto st209;
	goto st0;
st209:
	if ( ++p == pe )
		goto _test_eof209;
case 209:
	if ( (*p) == 65 )
		goto st210;
	goto st0;
st210:
	if ( ++p == pe )
		goto _test_eof210;
case 210:
	if ( (*p) == 77 )
		goto st211;
	goto st0;
st211:
	if ( ++p == pe )
		goto _test_eof211;
case 211:
	if ( (*p) == 69 )
		goto st212;
	goto st0;
st212:
	if ( ++p == pe )
		goto _test_eof212;
case 212:
	if ( (*p) == 84 )
		goto st213;
	goto st0;
st213:
	if ( ++p == pe )
		goto _test_eof213;
case 213:
	if ( (*p) == 69 )
		goto st214;
	goto st0;
st214:
	if ( ++p == pe )
		goto _test_eof214;
case 214:
	if ( (*p) == 82 )
		goto st215;
	goto st0;
st215:
	if ( ++p == pe )
		goto _test_eof215;
case 215:
	if ( (*p) == 32 )
		goto tr256;
	goto st0;
tr306:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st216;
st216:
	if ( ++p == pe )
		goto _test_eof216;
case 216:
#line 3689 "ebb_request_parser.c"
	switch( (*p) ) {
		case 69: goto st217;
		case 82: goto st224;
	}
	goto st0;
st217:
	if ( ++p == pe )
		goto _test_eof217;
case 217:
	if ( (*p) == 65 )
		goto st218;
	goto st0;
st218:
	if ( ++p == pe )
		goto _test_eof218;
case 218:
	if ( (*p) == 82 )
		goto st219;
	goto st0;
st219:
	if ( ++p == pe )
		goto _test_eof219;
case 219:
	if ( (*p) == 68 )
		goto st220;
	goto st0;
st220:
	if ( ++p == pe )
		goto _test_eof220;
case 220:
	if ( (*p) == 79 )
		goto st221;
	goto st0;
st221:
	if ( ++p == pe )
		goto _test_eof221;
case 221:
	if ( (*p) == 87 )
		goto st222;
	goto st0;
st222:
	if ( ++p == pe )
		goto _test_eof222;
case 222:
	if ( (*p) == 78 )
		goto st223;
	goto st0;
st223:
	if ( ++p == pe )
		goto _test_eof223;
case 223:
	if ( (*p) == 32 )
		goto tr265;
	goto st0;
st224:
	if ( ++p == pe )
		goto _test_eof224;
case 224:
	if ( (*p) == 65 )
		goto st225;
	goto st0;
st225:
	if ( ++p == pe )
		goto _test_eof225;
case 225:
	if ( (*p) == 67 )
		goto st226;
	goto st0;
st226:
	if ( ++p == pe )
		goto _test_eof226;
case 226:
	if ( (*p) == 69 )
		goto st227;
	goto st0;
st227:
	if ( ++p == pe )
		goto _test_eof227;
case 227:
	if ( (*p) == 32 )
		goto tr269;
	goto st0;
tr307:
#line 174 "ebb_request_parser.rl"
	{
    assert(CURRENT == NULL);
    CURRENT = parser->new_request(parser->data);
  }
	goto st228;
st228:
	if ( ++p == pe )
		goto _test_eof228;
case 228:
#line 3783 "ebb_request_parser.c"
	if ( (*p) == 78 )
		goto st229;
	goto st0;
st229:
	if ( ++p == pe )
		goto _test_eof229;
case 229:
	if ( (*p) == 76 )
		goto st230;
	goto st0;
st230:
	if ( ++p == pe )
		goto _test_eof230;
case 230:
	if ( (*p) == 79 )
		goto st231;
	goto st0;
st231:
	if ( ++p == pe )
		goto _test_eof231;
case 231:
	if ( (*p) == 67 )
		goto st232;
	goto st0;
st232:
	if ( ++p == pe )
		goto _test_eof232;
case 232:
	if ( (*p) == 75 )
		goto st233;
	goto st0;
st233:
	if ( ++p == pe )
		goto _test_eof233;
case 233:
	if ( (*p) == 32 )
		goto tr275;
	goto st0;
st234:
	if ( ++p == pe )
		goto _test_eof234;
case 234:
	if ( (*p) == 48 )
		goto tr276;
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr277;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr277;
	} else
		goto tr277;
	goto st0;
tr276:
#line 154 "ebb_request_parser.rl"
	{
    parser->chunk_size *= 16;
    parser->chunk_size += unhex[(int)*p];
  }
	goto st235;
st235:
	if ( ++p == pe )
		goto _test_eof235;
case 235:
#line 3848 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto st236;
		case 48: goto tr276;
		case 59: goto st249;
	}
	if ( (*p) < 65 ) {
		if ( 49 <= (*p) && (*p) <= 57 )
			goto tr277;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr277;
	} else
		goto tr277;
	goto st0;
st236:
	if ( ++p == pe )
		goto _test_eof236;
case 236:
	if ( (*p) == 10 )
		goto st237;
	goto st0;
st237:
	if ( ++p == pe )
		goto _test_eof237;
case 237:
	switch( (*p) ) {
		case 13: goto st238;
		case 33: goto st239;
		case 124: goto st239;
		case 126: goto st239;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st239;
		} else if ( (*p) >= 35 )
			goto st239;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st239;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st239;
		} else
			goto st239;
	} else
		goto st239;
	goto st0;
st238:
	if ( ++p == pe )
		goto _test_eof238;
case 238:
	if ( (*p) == 10 )
		goto tr283;
	goto st0;
tr283:
	cs = 253;
#line 169 "ebb_request_parser.rl"
	{
    END_REQUEST;
    cs = 252;
  }
	goto _again;
st253:
	if ( ++p == pe )
		goto _test_eof253;
case 253:
#line 3917 "ebb_request_parser.c"
	goto st0;
st239:
	if ( ++p == pe )
		goto _test_eof239;
case 239:
	switch( (*p) ) {
		case 33: goto st239;
		case 58: goto st240;
		case 124: goto st239;
		case 126: goto st239;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st239;
		} else if ( (*p) >= 35 )
			goto st239;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st239;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st239;
		} else
			goto st239;
	} else
		goto st239;
	goto st0;
st240:
	if ( ++p == pe )
		goto _test_eof240;
case 240:
	if ( (*p) == 13 )
		goto st236;
	goto st240;
tr277:
#line 154 "ebb_request_parser.rl"
	{
    parser->chunk_size *= 16;
    parser->chunk_size += unhex[(int)*p];
  }
	goto st241;
st241:
	if ( ++p == pe )
		goto _test_eof241;
case 241:
#line 3965 "ebb_request_parser.c"
	switch( (*p) ) {
		case 13: goto st242;
		case 59: goto st246;
	}
	if ( (*p) < 65 ) {
		if ( 48 <= (*p) && (*p) <= 57 )
			goto tr277;
	} else if ( (*p) > 70 ) {
		if ( 97 <= (*p) && (*p) <= 102 )
			goto tr277;
	} else
		goto tr277;
	goto st0;
st242:
	if ( ++p == pe )
		goto _test_eof242;
case 242:
	if ( (*p) == 10 )
		goto st243;
	goto st0;
st243:
	if ( ++p == pe )
		goto _test_eof243;
case 243:
	goto tr288;
tr288:
#line 159 "ebb_request_parser.rl"
	{
    skip_body(&p, parser, MIN(parser->chunk_size, REMAINING));
    p--; 
    if(parser->chunk_size > REMAINING) {
      {p++; cs = 244; goto _out;}
    } else {
      {goto st244;} 
    }
  }
	goto st244;
st244:
	if ( ++p == pe )
		goto _test_eof244;
case 244:
#line 4007 "ebb_request_parser.c"
	if ( (*p) == 13 )
		goto st245;
	goto st0;
st245:
	if ( ++p == pe )
		goto _test_eof245;
case 245:
	if ( (*p) == 10 )
		goto st234;
	goto st0;
st246:
	if ( ++p == pe )
		goto _test_eof246;
case 246:
	switch( (*p) ) {
		case 13: goto st242;
		case 32: goto st246;
		case 33: goto st247;
		case 59: goto st246;
		case 61: goto st248;
		case 124: goto st247;
		case 126: goto st247;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st247;
		} else if ( (*p) >= 35 )
			goto st247;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st247;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st247;
		} else
			goto st247;
	} else
		goto st247;
	goto st0;
st247:
	if ( ++p == pe )
		goto _test_eof247;
case 247:
	switch( (*p) ) {
		case 13: goto st242;
		case 33: goto st247;
		case 59: goto st246;
		case 61: goto st248;
		case 124: goto st247;
		case 126: goto st247;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st247;
		} else if ( (*p) >= 35 )
			goto st247;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st247;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st247;
		} else
			goto st247;
	} else
		goto st247;
	goto st0;
st248:
	if ( ++p == pe )
		goto _test_eof248;
case 248:
	switch( (*p) ) {
		case 13: goto st242;
		case 33: goto st248;
		case 59: goto st246;
		case 124: goto st248;
		case 126: goto st248;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st248;
		} else if ( (*p) >= 35 )
			goto st248;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st248;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st248;
		} else
			goto st248;
	} else
		goto st248;
	goto st0;
st249:
	if ( ++p == pe )
		goto _test_eof249;
case 249:
	switch( (*p) ) {
		case 13: goto st236;
		case 32: goto st249;
		case 33: goto st250;
		case 59: goto st249;
		case 61: goto st251;
		case 124: goto st250;
		case 126: goto st250;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st250;
		} else if ( (*p) >= 35 )
			goto st250;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st250;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st250;
		} else
			goto st250;
	} else
		goto st250;
	goto st0;
st250:
	if ( ++p == pe )
		goto _test_eof250;
case 250:
	switch( (*p) ) {
		case 13: goto st236;
		case 33: goto st250;
		case 59: goto st249;
		case 61: goto st251;
		case 124: goto st250;
		case 126: goto st250;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st250;
		} else if ( (*p) >= 35 )
			goto st250;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st250;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st250;
		} else
			goto st250;
	} else
		goto st250;
	goto st0;
st251:
	if ( ++p == pe )
		goto _test_eof251;
case 251:
	switch( (*p) ) {
		case 13: goto st236;
		case 33: goto st251;
		case 59: goto st249;
		case 124: goto st251;
		case 126: goto st251;
	}
	if ( (*p) < 45 ) {
		if ( (*p) > 39 ) {
			if ( 42 <= (*p) && (*p) <= 43 )
				goto st251;
		} else if ( (*p) >= 35 )
			goto st251;
	} else if ( (*p) > 46 ) {
		if ( (*p) < 65 ) {
			if ( 48 <= (*p) && (*p) <= 57 )
				goto st251;
		} else if ( (*p) > 90 ) {
			if ( 94 <= (*p) && (*p) <= 122 )
				goto st251;
		} else
			goto st251;
	} else
		goto st251;
	goto st0;
	}
	_test_eof252: cs = 252; goto _test_eof; 
	_test_eof1: cs = 1; goto _test_eof; 
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof73: cs = 73; goto _test_eof; 
	_test_eof74: cs = 74; goto _test_eof; 
	_test_eof75: cs = 75; goto _test_eof; 
	_test_eof76: cs = 76; goto _test_eof; 
	_test_eof77: cs = 77; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
	_test_eof97: cs = 97; goto _test_eof; 
	_test_eof98: cs = 98; goto _test_eof; 
	_test_eof99: cs = 99; goto _test_eof; 
	_test_eof100: cs = 100; goto _test_eof; 
	_test_eof101: cs = 101; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof118: cs = 118; goto _test_eof; 
	_test_eof119: cs = 119; goto _test_eof; 
	_test_eof120: cs = 120; goto _test_eof; 
	_test_eof121: cs = 121; goto _test_eof; 
	_test_eof122: cs = 122; goto _test_eof; 
	_test_eof123: cs = 123; goto _test_eof; 
	_test_eof124: cs = 124; goto _test_eof; 
	_test_eof125: cs = 125; goto _test_eof; 
	_test_eof126: cs = 126; goto _test_eof; 
	_test_eof127: cs = 127; goto _test_eof; 
	_test_eof128: cs = 128; goto _test_eof; 
	_test_eof129: cs = 129; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 
	_test_eof132: cs = 132; goto _test_eof; 
	_test_eof133: cs = 133; goto _test_eof; 
	_test_eof134: cs = 134; goto _test_eof; 
	_test_eof135: cs = 135; goto _test_eof; 
	_test_eof136: cs = 136; goto _test_eof; 
	_test_eof137: cs = 137; goto _test_eof; 
	_test_eof138: cs = 138; goto _test_eof; 
	_test_eof139: cs = 139; goto _test_eof; 
	_test_eof140: cs = 140; goto _test_eof; 
	_test_eof141: cs = 141; goto _test_eof; 
	_test_eof142: cs = 142; goto _test_eof; 
	_test_eof143: cs = 143; goto _test_eof; 
	_test_eof144: cs = 144; goto _test_eof; 
	_test_eof145: cs = 145; goto _test_eof; 
	_test_eof146: cs = 146; goto _test_eof; 
	_test_eof147: cs = 147; goto _test_eof; 
	_test_eof148: cs = 148; goto _test_eof; 
	_test_eof149: cs = 149; goto _test_eof; 
	_test_eof150: cs = 150; goto _test_eof; 
	_test_eof151: cs = 151; goto _test_eof; 
	_test_eof152: cs = 152; goto _test_eof; 
	_test_eof153: cs = 153; goto _test_eof; 
	_test_eof154: cs = 154; goto _test_eof; 
	_test_eof155: cs = 155; goto _test_eof; 
	_test_eof156: cs = 156; goto _test_eof; 
	_test_eof157: cs = 157; goto _test_eof; 
	_test_eof158: cs = 158; goto _test_eof; 
	_test_eof159: cs = 159; goto _test_eof; 
	_test_eof160: cs = 160; goto _test_eof; 
	_test_eof161: cs = 161; goto _test_eof; 
	_test_eof162: cs = 162; goto _test_eof; 
	_test_eof163: cs = 163; goto _test_eof; 
	_test_eof164: cs = 164; goto _test_eof; 
	_test_eof165: cs = 165; goto _test_eof; 
	_test_eof166: cs = 166; goto _test_eof; 
	_test_eof167: cs = 167; goto _test_eof; 
	_test_eof168: cs = 168; goto _test_eof; 
	_test_eof169: cs = 169; goto _test_eof; 
	_test_eof170: cs = 170; goto _test_eof; 
	_test_eof171: cs = 171; goto _test_eof; 
	_test_eof172: cs = 172; goto _test_eof; 
	_test_eof173: cs = 173; goto _test_eof; 
	_test_eof174: cs = 174; goto _test_eof; 
	_test_eof175: cs = 175; goto _test_eof; 
	_test_eof176: cs = 176; goto _test_eof; 
	_test_eof177: cs = 177; goto _test_eof; 
	_test_eof178: cs = 178; goto _test_eof; 
	_test_eof179: cs = 179; goto _test_eof; 
	_test_eof180: cs = 180; goto _test_eof; 
	_test_eof181: cs = 181; goto _test_eof; 
	_test_eof182: cs = 182; goto _test_eof; 
	_test_eof183: cs = 183; goto _test_eof; 
	_test_eof184: cs = 184; goto _test_eof; 
	_test_eof185: cs = 185; goto _test_eof; 
	_test_eof186: cs = 186; goto _test_eof; 
	_test_eof187: cs = 187; goto _test_eof; 
	_test_eof188: cs = 188; goto _test_eof; 
	_test_eof189: cs = 189; goto _test_eof; 
	_test_eof190: cs = 190; goto _test_eof; 
	_test_eof191: cs = 191; goto _test_eof; 
	_test_eof192: cs = 192; goto _test_eof; 
	_test_eof193: cs = 193; goto _test_eof; 
	_test_eof194: cs = 194; goto _test_eof; 
	_test_eof195: cs = 195; goto _test_eof; 
	_test_eof196: cs = 196; goto _test_eof; 
	_test_eof197: cs = 197; goto _test_eof; 
	_test_eof198: cs = 198; goto _test_eof; 
	_test_eof199: cs = 199; goto _test_eof; 
	_test_eof200: cs = 200; goto _test_eof; 
	_test_eof201: cs = 201; goto _test_eof; 
	_test_eof202: cs = 202; goto _test_eof; 
	_test_eof203: cs = 203; goto _test_eof; 
	_test_eof204: cs = 204; goto _test_eof; 
	_test_eof205: cs = 205; goto _test_eof; 
	_test_eof206: cs = 206; goto _test_eof; 
	_test_eof207: cs = 207; goto _test_eof; 
	_test_eof208: cs = 208; goto _test_eof; 
	_test_eof209: cs = 209; goto _test_eof; 
	_test_eof210: cs = 210; goto _test_eof; 
	_test_eof211: cs = 211; goto _test_eof; 
	_test_eof212: cs = 212; goto _test_eof; 
	_test_eof213: cs = 213; goto _test_eof; 
	_test_eof214: cs = 214; goto _test_eof; 
	_test_eof215: cs = 215; goto _test_eof; 
	_test_eof216: cs = 216; goto _test_eof; 
	_test_eof217: cs = 217; goto _test_eof; 
	_test_eof218: cs = 218; goto _test_eof; 
	_test_eof219: cs = 219; goto _test_eof; 
	_test_eof220: cs = 220; goto _test_eof; 
	_test_eof221: cs = 221; goto _test_eof; 
	_test_eof222: cs = 222; goto _test_eof; 
	_test_eof223: cs = 223; goto _test_eof; 
	_test_eof224: cs = 224; goto _test_eof; 
	_test_eof225: cs = 225; goto _test_eof; 
	_test_eof226: cs = 226; goto _test_eof; 
	_test_eof227: cs = 227; goto _test_eof; 
	_test_eof228: cs = 228; goto _test_eof; 
	_test_eof229: cs = 229; goto _test_eof; 
	_test_eof230: cs = 230; goto _test_eof; 
	_test_eof231: cs = 231; goto _test_eof; 
	_test_eof232: cs = 232; goto _test_eof; 
	_test_eof233: cs = 233; goto _test_eof; 
	_test_eof234: cs = 234; goto _test_eof; 
	_test_eof235: cs = 235; goto _test_eof; 
	_test_eof236: cs = 236; goto _test_eof; 
	_test_eof237: cs = 237; goto _test_eof; 
	_test_eof238: cs = 238; goto _test_eof; 
	_test_eof253: cs = 253; goto _test_eof; 
	_test_eof239: cs = 239; goto _test_eof; 
	_test_eof240: cs = 240; goto _test_eof; 
	_test_eof241: cs = 241; goto _test_eof; 
	_test_eof242: cs = 242; goto _test_eof; 
	_test_eof243: cs = 243; goto _test_eof; 
	_test_eof244: cs = 244; goto _test_eof; 
	_test_eof245: cs = 245; goto _test_eof; 
	_test_eof246: cs = 246; goto _test_eof; 
	_test_eof247: cs = 247; goto _test_eof; 
	_test_eof248: cs = 248; goto _test_eof; 
	_test_eof249: cs = 249; goto _test_eof; 
	_test_eof250: cs = 250; goto _test_eof; 
	_test_eof251: cs = 251; goto _test_eof; 

	_test_eof: {}
	_out: {}
	}

#line 375 "ebb_request_parser.rl"

  parser->cs = cs;

  HEADER_CALLBACK(header_field);
  HEADER_CALLBACK(header_value);
  CALLBACK(fragment);
  CALLBACK(query_string);
  CALLBACK(path);
  CALLBACK(uri);

  assert(p <= pe && "buffer overflow after parsing execute");

  return(p - buffer);
}

int ebb_request_parser_has_error(ebb_request_parser *parser) 
{
  return parser->cs == ebb_request_parser_error;
}

int ebb_request_parser_is_finished(ebb_request_parser *parser) 
{
  return parser->cs == ebb_request_parser_first_final;
}

void ebb_request_init(ebb_request *request)
{
  request->expect_continue = FALSE;
  request->body_read = 0;
  request->content_length = 0;
  request->method = 0;
  request->protocol = 0;
  request->version_major = 0;
  request->version_minor = 0;
  request->number_of_headers = 0;
  request->transfer_encoding = EBB_IDENTITY;
  request->keep_alive = -1;

  request->on_complete = NULL;
  request->on_headers_complete = NULL;
  request->on_body = NULL;
  request->on_header_field = NULL;
  request->on_header_value = NULL;
  request->on_uri = NULL;
  request->on_fragment = NULL;
  request->on_path = NULL;
  request->on_query_string = NULL;
}

int ebb_request_should_keep_alive(ebb_request *request)
{
  if(request->keep_alive == -1)
    if(request->protocol == EBB_PROTOCOL_RTSP)
      return TRUE;
    else if(request->version_major == 1)
      return (request->version_minor != 0);
    else if(request->version_major == 0)
      return FALSE;
    else
      return TRUE;
  else
    return request->keep_alive;
}
