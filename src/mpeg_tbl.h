#ifndef MPEG_TBL_H
#define MPEG_TBL_H

#include "global.h"

#define MPEG_HILO(x) (x##_hi << 8 | x##_lo)

#define PSI_TABLE_ID_PAT (0x00)
#define PSI_TABLE_ID_CAT (0x01)
#define PSI_TABLE_ID_PMT (0x02)
#define PSI_TABLE_ID_SDT (0x42)

#define PRIV_SECTION_LEN_FIXUP (3)

struct private_section_hdr {
    uint8_t	table_id;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	section_syntax_indicator:1;
    uint8_t	unused:3;
    uint8_t	section_length_hi:4;
#else
    uint8_t	section_length_hi:4;
    uint8_t	unused:3;
    uint8_t	section_syntax_indicator:1;
#endif
    uint8_t	section_length_lo;
};

struct private_section_ext_hdr {
    uint8_t	table_id;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	section_syntax_indicator:1;
    uint8_t	unused:3;
    uint8_t	section_length_hi:4;
#else
    uint8_t	section_length_hi:4;
    uint8_t	unused:3;
    uint8_t	section_syntax_indicator:1;
#endif
    uint8_t	section_length_lo;
    uint8_t	table_id_extension_hi;
    uint8_t	table_id_extension_lo;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused2:2;
    uint8_t	version_number:5;
    uint8_t	current_next_indicator:1;
#else
    uint8_t	current_next_indicator:1;
    uint8_t	version_number:5;
    uint8_t	unused2:2;
#endif
    uint8_t	section_number;
    uint8_t	last_section_number;
};

struct descriptor_hdr {
    uint8_t	descriptor_tag;
    uint8_t	descriptor_length;
};

#define PAT_LEN 8
#define PAT_LEN_FIX 3
struct pat {
    uint8_t	table_id;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	section_syntax_indicator:1;
    uint8_t	dummy:1;
    uint8_t	unused:2;
    uint8_t	section_length_hi:4;
#else
    uint8_t	section_length_hi:4;
    uint8_t	unused:2;
    uint8_t	dummy:1;
    uint8_t	section_syntax_indicator:1;
#endif
    uint8_t	section_length_lo;
    uint8_t	transport_stream_id_hi;
    uint8_t	transport_stream_id_lo;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused2:2;
    uint8_t	version_number:5;
    uint8_t	current_next_indicator:1;
#else
    uint8_t	current_next_indicator:1;
    uint8_t	version_number:5;
    uint8_t	unused2:2;
#endif
    uint8_t	section_number;
    uint8_t	last_section_number;
};

#define PAT_PROG_LEN 4
struct pat_prog {
    uint8_t	program_number_hi;
    uint8_t	program_number_lo;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused:3;
    uint8_t	network_pid_hi:5;
#else
    uint8_t	network_pid_hi:5;
    uint8_t	unused:3;
#endif
    uint8_t	network_pid_lo;
};

#define PMT_LEN 12
#define PMT_LEN_FIX 3
struct pmt {
    uint8_t	table_id;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	section_syntax_indicator:1;
    uint8_t	dummy:1;
    uint8_t	unused:2;
    uint8_t	section_length_hi:4;
#else
    uint8_t	section_length_hi:4;
    uint8_t	unused:2;
    uint8_t	dummy:1;
    uint8_t	section_syntax_indicator:1;
#endif
    uint8_t	section_length_lo;
    uint8_t	program_number_hi;
    uint8_t	program_number_lo;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused2:2;
    uint8_t	version_number:5;
    uint8_t	current_next_indicator:1;
#else
    uint8_t	current_next_indicator:1;
    uint8_t	version_number:5;
    uint8_t	unused2:2;
#endif
    uint8_t	section_number;
    uint8_t	last_section_number;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused3:3;
    uint8_t	PCR_PID_hi:5;
#else
    uint8_t	PCR_PID_hi:5;
    uint8_t	unused3:3;
#endif
    uint8_t	PCR_PID_lo;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused4:4;
    uint8_t	program_info_length_hi:4;
#else
    uint8_t	program_info_length_hi:4;
    uint8_t	unused4:4;
#endif
    uint8_t	program_info_length_lo;
    /* descriptor_loop */
};

#define PMT_INFO_LEN 5
struct pmt_info {
    uint8_t	stream_type;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused:3;
    uint8_t	elementary_PID_hi:5;
#else
    uint8_t	elementary_PID_hi:5;
    uint8_t	unused:3;
#endif
    uint8_t	elementary_PID_lo;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused2:4;
    uint8_t	ES_info_length_hi:4;
#else
    uint8_t	ES_info_length_hi:4;
    uint8_t	unused2:4;
#endif
    uint8_t	ES_info_length_lo;
    /* descriptor_loop */
};

#define SDT_LEN 11
#define SDT_LEN_FIX 3
struct sdt {
    uint8_t	table_id;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	section_syntax_indicator:1;
    uint8_t	unused:3;
    uint8_t	section_length_hi:4;
#else
    uint8_t	section_length_hi:4;
    uint8_t	unused:3;
    uint8_t	section_syntax_indicator:1;
#endif
    uint8_t	section_length_lo;
    uint8_t	transport_stream_id_hi;
    uint8_t	transport_stream_id_lo;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused2:2;
    uint8_t	version_number:5;
    uint8_t	current_next_indicator:1;
#else
    uint8_t	current_next_indicator:1;
    uint8_t	version_number:5;
    uint8_t	unused2:2;
#endif
    uint8_t	section_number;
    uint8_t	last_section_number;
    uint8_t	original_network_id_hi;
    uint8_t	original_network_id_lo;
    uint8_t	unused3;
};

#define SDT_DESCR_LEN 5
struct sdt_descr {
    uint8_t	service_id_hi;
    uint8_t	service_id_lo;
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t	unused:6;
    uint8_t	eit_schedule_flag:1;
    uint8_t	eit_present_following_flag:1;
    uint8_t	running_status:3;
    uint8_t	free_ca_mode:1;
    uint8_t	descriptors_loop_length_hi:4;
#else
    uint8_t	eit_present_following_flag:1;
    uint8_t	eit_schedule_flag:1;
    uint8_t	unused:6;
    uint8_t	descriptors_loop_length_hi:4;
    uint8_t	free_ca_mode:1;
    uint8_t	running_status:3;
#endif
    uint8_t	descriptors_loop_length_lo;
    /* descriptor_loop */
};

#define descriptor_id_Service_Descriptor (0x48)
#define Service_Descriptor_Max_StrLen (0xff)
struct service_descriptor {
    uint8_t	descriptor_tag;
    uint8_t	descriptor_length;

    uint8_t	service_type;
    uint8_t	service_provider_name_length;
/*  uint8_t	service_provider_name[VAR_LEN]; */
/*  uint8_t	service_name_length; */
/*  uint8_t	service_name[VAR_LEN]; */
};

#define SDT_service_provider_name_length(s) ((s)->service_provider_name_length)
#define SDT_service_provider_name(s) (((char*) (s)) + sizeof(struct service_descriptor))

#define SDT_service_name_length(s) ( ((uint8_t*) (s)) [sizeof(struct service_descriptor) + SDT_service_provider_name_length(s)])
#define SDT_service_name(s) (((char*) (s)) + sizeof(struct service_descriptor) + SDT_service_provider_name_length(s) + sizeof(uint8_t))

#define descriptor_id_CA (9)

#endif /* MPEG_TBL_H */
