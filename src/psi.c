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

#include <errno.h>
#include <ctype.h>

#define LOG_MODULE ("psi")
#define LOG_PARAM (this->mpegio_identifier)

#include "global.h"
#include "utils.h"
#include "psi.h"
#include "csconv.h"

#include <assert.h>

#ifdef MALLOC_DEBUG
#include "duma.h"
#endif

#define PSI_PID_HASH(x) ( ((x) ^ ((x) >> 4) ^ ((x) >> 8) ) & PSI_PID_HASHMASK )
#define PSI_HT_DEPTHWARN (6)

#define SECT_MAX_DATA_SIZE (0xfff + sizeof(struct private_section_hdr))

struct si_reassemply {
    struct si_reassemply *next;

    uint16_t flags;
    uint16_t pid;

    uint16_t pos;
    uint16_t length;
    uint8_t seq;
    uint8_t data[SECT_MAX_DATA_SIZE];
};

struct pid_descriptor {
    struct pid_descriptor *next;

    uint32_t data_hash;

    uint16_t pid;
    uint16_t flags;

    union {
	struct info_pmt {
	    uint16_t program_number;
	    int8_t version;
	} pmt;
	struct info_es {
	    uint16_t sid;
	    uint8_t type;
	} es;
    };
};

#define SDT_NAME_LEN (255)

#define PROGRAM_INVALID (0xffff)
#define IS_PMT_LOADED (this->pmt_program_id != PROGRAM_INVALID)

struct mpeg_psi {
    int cat_version;
    int pat_version;
    int sdt_version;

    uint16_t pmt_program_id;
    const char *mpegio_identifier;

    int sdt_mangle_serial;
    int sdt_mangle_curr_serial;
    char *current_provider_name;
    char *current_service_name;

    struct pid_descriptor *pids_info[PSI_PID_HASHMASK+1];
    struct pid_descriptor *pids_pool;

    /* TODO GC old data*/
    struct si_reassemply *reassemply_hash[SECT_REASSEMBL_HASHMASK+1];
    struct si_reassemply *reassemply_pool;
};

#define this (_this)
#define THIS PSI _this

/*************************************************************************/

static void psi_pid_descriptor_free(THIS, struct pid_descriptor *descr);
static void si_reassem_free(THIS, struct si_reassemply *r);

static void mpeg_psi_pat(THIS, uint8_t *data, int data_len);
static void mpeg_psi_sdt(THIS, uint8_t *data, int data_len);
static void mpeg_psi_pmt(THIS, uint16_t pid, uint8_t *data, int data_len);

/*************************************************************************/

struct mpeg_psi *psi_alloc()
{
    struct mpeg_psi *_this;

    _this = xmalloc(sizeof(struct mpeg_psi));

    memset(_this, 0, sizeof(struct mpeg_psi));

    return _this;
}

int psi_init(THIS, const char *identifier)
{
    this->mpegio_identifier = identifier;

    this->cat_version = -1;
    this->pat_version = -1;
    this->sdt_version = -1;

    this->pmt_program_id = PROGRAM_INVALID;
    this->sdt_mangle_serial = 0;
    this->sdt_mangle_curr_serial = 0;

    this->current_provider_name = xmalloc(SDT_NAME_LEN+1);
    this->current_service_name = xmalloc(SDT_NAME_LEN+1);

    this->current_provider_name[0] = 0;
    this->current_service_name[0] = 0;

    return 0;
}

static void psi_cleanup_pids_list(THIS, struct pid_descriptor *list)
{
    struct pid_descriptor *head, *next;

    head = list;
    while (head) {
	next = head->next;
	head->next = NULL;
	psi_pid_descriptor_free(this, head);
	head = next;
    };
}

static void psi_cleanup_pids(THIS)
{
    int ht;

    /* release data from hash table */
    for (ht=0; ht<PSI_PID_HASHMASK; ht++){
	psi_cleanup_pids_list(this, this->pids_info[ht]);
	this->pids_info[ht] = NULL;
    }

    /* free pool */
    psi_cleanup_pids_list(this, this->pids_pool);
    this->pids_pool = NULL;
}

static void psi_cleanup_reassem_list(THIS, struct si_reassemply *list)
{
    struct si_reassemply *head, *next;

    head = list;
    while (head) {
	next = head->next;
	head->next = NULL;
	si_reassem_free(this, head);
	head = next;
    };
}

static void psi_cleanup_reassem(THIS)
{
    int ht;

    /* release data from hash table */
    for (ht=0; ht<SECT_REASSEMBL_HASHMASK; ht++){
	psi_cleanup_reassem_list(this, this->reassemply_hash[ht]);
	this->reassemply_hash[ht] = NULL;
    }

    /* free pool */
    psi_cleanup_reassem_list(this, this->reassemply_pool);
    this->reassemply_pool = NULL;
}

void psi_cleanup(THIS)
{
    xfree(this->current_provider_name);
    xfree(this->current_service_name);

    psi_cleanup_pids(this);
    psi_cleanup_reassem(this);

    xfree(this);
}

struct pid_descriptor *psi_pid_descriptor_alloc(THIS)
{
    struct pid_descriptor *res;

    if (this->pids_pool){
	res = this->pids_pool;
	this->pids_pool = res->next;
    } else {
	res = xmalloc(sizeof(struct pid_descriptor));
    }

    res->next = NULL;
    return res;
}

void psi_pid_descriptor_free(THIS, struct pid_descriptor *descr)
{
    xfree(descr);
}

void psi_pid_descriptor_release(THIS, struct pid_descriptor *p)
{
    struct pid_descriptor *d;
    int ht;

    ht = PSI_PID_HASH(p->pid);

    d = this->pids_info[ht];

    if (d == p){
	this->pids_info[ht] = p->next;
	p->next = this->pids_pool;
	this->pids_pool = p;
	return;
    }

    while (d != NULL && d->next != NULL){
	if (d->next == p){
	    d->next = p->next;
	    p->next = this->pids_pool;
	    this->pids_pool = p;
	    return;
	}
	d = d->next;
    }

    log_error("psi: trying to release pid descriptor not in hash table");
}

int psi_pid_register(THIS, struct pid_descriptor *p)
{
    int ht;

    ht = PSI_PID_HASH(p->pid);

    p->next = this->pids_info[ht];
    this->pids_info[ht] = p;

    return 0;
}

struct pid_descriptor *psi_pid_lookup(THIS, uint16_t pid)
{
    struct pid_descriptor *d;
    struct pid_descriptor *dprev = NULL;
    int ht;
    int depth = 0;

    ht = PSI_PID_HASH(pid);

    for (d=this->pids_info[ht]; d; d=d->next){
	if (d->pid == pid){
	    if (depth > PSI_HT_DEPTHWARN){
		/* TODO, count warnings */
		log_warning("psi hashtable is too deep, moving element to the head");
		assert(dprev);
		dprev->next = d->next;
		d->next = this->pids_info[ht];
		this->pids_info[ht] = d;
	    }
	    return d;
	}
	
	depth++;
	dprev = d;
    }

    return NULL;
}

/* FIXME slow lookup function */
struct pid_descriptor *psi_pid_lookup_hash(THIS, uint32_t hash)
{
    struct pid_descriptor *d;
    int ht;


    for (ht=0; ht<(PSI_PID_HASHMASK+1); ht++){
	for (d=this->pids_info[ht]; d; d=d->next){
	    if (d->data_hash == hash)
		return d;
	}
    }

    return NULL;
}


int psi_pid_lookup_flags(THIS, uint16_t pid)
{
    struct pid_descriptor *d;

    d = psi_pid_lookup(this, pid);

    if (d == NULL){
	return PSI_PID_TYPE_UNREF;
    }

    return d->flags;
}

void psi_pids_flush(THIS)
{
    int i;

    for (i=0;i<PSI_PID_HASHMASK+1;i++){
	if (this->pids_info[i]){
	    this->pids_info[i]->next = this->pids_pool;
	    this->pids_pool = this->pids_info[i];
	    this->pids_info[i] = NULL;
	}
    }
}




static void si_reassem_release(THIS, struct si_reassemply *r)
{
    struct si_reassemply *prev;

    prev = this->reassemply_hash[r->pid & SECT_REASSEMBL_HASHMASK];

    if (prev == r) {
	this->reassemply_hash[r->pid & SECT_REASSEMBL_HASHMASK] = r->next;
    } else {
	do {
	    if (prev->next == r){
		prev->next = r->next;
		break;
	    }

	    prev = prev->next;
	} while (prev->next);
    }

    r->next = this->reassemply_pool;
    this->reassemply_pool = r;

    r->flags = 0;
    r->pid = 0;
    r->pos = 0;
    r->length = 0;
}

static struct si_reassemply *si_reassem_alloc(THIS)
{
    struct si_reassemply *r;

    if (this->reassemply_pool){
	r = this->reassemply_pool;
	this->reassemply_pool = r->next;
    } else {
	r = xmalloc(sizeof(struct si_reassemply));
    }

    r->next = NULL;
    r->flags = 0;
    r->pid = 0;
    r->pos = 0;

    return r;
}

void si_reassem_free(THIS, struct si_reassemply *r)
{
    xfree(r);
}

static struct si_reassemply *si_reassem_lookup(THIS, uint16_t pid)
{
    struct si_reassemply *r;

    r = this->reassemply_hash[pid & SECT_REASSEMBL_HASHMASK];
    while (r){

	if (r->pid == pid)
	    return r;

	r = r->next;
    }

    /* new item */
    r = si_reassem_alloc(this);
    r->pid = pid;

    r->next = this->reassemply_hash[pid & SECT_REASSEMBL_HASHMASK];
    this->reassemply_hash[pid & SECT_REASSEMBL_HASHMASK] = r;

    return r;
}

int psi_reassemply_finished(THIS, struct si_reassemply *r)
{
    if (verbose>2)
	log_info("reassembly ok %d %d  %d", r->pid, r->flags, r->length);

    switch (PSI_PID_TYPE(r->flags)){
	case PSI_PID_TYPE_PAT:
	    mpeg_psi_pat(this, r->data, r->length);
	    break;
	case PSI_PID_TYPE_SDT:
	    mpeg_psi_sdt(this, r->data, r->length);
	    break;
	case PSI_PID_TYPE_PMT:
	    mpeg_psi_pmt(this, r->pid, r->data, r->length);
	    break;
    }

    si_reassem_release(this, r);
    return 0;
}

static size_t mpeg_get_payload_len(const uint8_t *pkt)
{
    int offs = MPEG_HEADER_LEN;

    if (pkt[0] != MPEG_SYNC){
	return 0;
    }

    if (MPEG_HDR_AF(pkt))
	offs += MPEG_HDR_AF_LEN(pkt) + 1;

    if (offs >= MPEG_PKT_SIZE){
	return 0;
    }

    return MPEG_PKT_SIZE - offs;
}

int psi_submit_for_reassemply(THIS, uint16_t pid, uint16_t flags, uint8_t *pkt)
{
    struct si_reassemply *r;
    uint8_t *payload;
    struct private_section_hdr *hdr;
    size_t payload_size;
    size_t copylen, copyleft;
    uint8_t new_seq, pointer_offs;

    if (MPEG_HDR_TEI(pkt)) {
	log_warning("mpegio: dropping packet submitted for reassembly with transport error flag set");
	return -1;
    }

    r = si_reassem_lookup(this, pid);

    payload_size = mpeg_get_payload_len(pkt);

    if (payload_size <= 0) {
	return -1;
    }

    payload = pkt + MPEG_PKT_SIZE - payload_size;

    if (r->pos == 0) {
	/* wait for unit start */
	if (!MPEG_HDR_PUS(pkt))
	    return -1;

	pointer_offs = payload[0];

	if (payload_size < sizeof(struct private_section_hdr) + pointer_offs + 1) {
	    log_warning("invalid packet received");
	    return -1;
	}

	payload += pointer_offs+1;
	payload_size -= pointer_offs+1;

	hdr = (void*)payload;

	r->length = MPEG_HILO(hdr->section_length) + PRIV_SECTION_LEN_FIXUP;
	r->seq = MPEG_HDR_CNT(pkt);
	r->flags = flags;

	if (r->length > SECT_MAX_DATA_SIZE){
	    log_error("reassembled packet too large %d, max: %d", r->length, SECT_MAX_DATA_SIZE);
	    return -1;
	}
    } else {
	/* check packet sequence */
	new_seq = MPEG_HDR_CNT(pkt);

	if (MPEG_HDR_CNT_NEXT(r->seq) != new_seq) {
	    log_warning("mpeg pid 0x%x reassembply failed, packet loss", pid);
	    si_reassem_release(this, r);
	    return -1;
	}

	if (r->flags != flags) {
	    log_error("mpeg pid 0x%x packet flags changed during disassembply", pid);
	    si_reassem_release(this, r);
	    return -1;
	}

	r->seq = new_seq;
    }

    assert(r->length > r->pos);

    copyleft = r->length - r->pos;
    copylen = payload_size < copyleft ? payload_size : copyleft;

    assert(r->pos + copylen <= SECT_MAX_DATA_SIZE);
    memcpy(&r->data[r->pos], payload, copylen);

    r->pos += copylen;

    assert (r->pos <= r->length);

    if (r->pos == r->length) {
	return psi_reassemply_finished(this, r);
    }

    return 0;
}


/***************************************************************************************/


static void mpeg_psi_pat(THIS, uint8_t *data, int data_len)
{
    struct pid_descriptor *d;
    struct pat *pat;
    struct pat_prog *pat_prog;
    int p_offs, p_len;
    int sect_len;
    uint32_t crc;
    int pid;

    pat = (struct pat*)data;

    sect_len = MPEG_HILO(pat->section_length);

    if (MPEG_HILO(pat->section_length) + 3 > data_len)
	return;

    pat_prog = (void*)data + PAT_LEN;

    /* these checks are safe before crc validation:
     * if crc is ok - packed will be dropped
     * if crc is broken and conditions are true, packet will be dropped
     */

    if (pat->current_next_indicator == 0){
	/* we are not interested in 'next' tables */
	return;
    }

    if (pat->version_number == this->pat_version){
	/* same version */
	return;
    }


    if (crc32_check(data, sect_len + PAT_LEN_FIX, CRC32_INIT)){
	log_warning("psi pat crc error");
	return;
    }

    crc = *(uint32_t*)(&data[sect_len + PAT_LEN_FIX - MPEG_PSI_CRC_LEN]);


    if (pat->table_id != PSI_TABLE_ID_PAT){
	log_warning("psi pat invalid table_id: 0x%x", pat->table_id);
	return;
    }

    d = psi_pid_lookup(this, MPEG_PID_PAT);

    if (d){
	if (pat->version_number == this->pat_version){
	    return;
	}
	d->pid = MPEG_PID_PAT;
	d->flags = PSI_PID_PAT_FLAGS;
	d->data_hash = crc;
    } else {
	d = psi_pid_descriptor_alloc(this);

	d->pid = MPEG_PID_PAT;
	d->flags = PSI_PID_PAT_FLAGS;
	d->data_hash = crc;

	psi_pid_register(this, d);
    }

    log_info("PAT: table_id: %d, len: %d, ts id: 0x%04x, version: %d", pat->table_id, MPEG_HILO(pat->section_length),
		MPEG_HILO(pat->transport_stream_id), pat->version_number);

    this->pat_version = pat->version_number;

    /* XXX FIXME: find way to release stale entries
     * cant't to release all of them on new pat or pmt because
     * streaming can be disturbed
     */

    p_offs = 0;
    p_len = sect_len + PAT_LEN_FIX - (PAT_LEN + MPEG_PSI_CRC_LEN);

    while (p_offs < p_len) {
	pat_prog = (void*)data + PAT_LEN + p_offs;

	pid = MPEG_HILO(pat_prog->network_pid);

	log_info("\t prog: %d, pid: 0x%04x", MPEG_HILO(pat_prog->program_number), pid);

	d = psi_pid_lookup(this, pid);
	if (d == NULL) {
	    d = psi_pid_descriptor_alloc(this);

	    d->pid = pid;
	    d->flags = PSI_PID_PMT_FLAGS;
	    d->pmt.program_number = MPEG_HILO(pat_prog->program_number);
	    d->data_hash = 0;

	    psi_pid_register(this, d);
	} else {
	    if (d->flags != PSI_PID_PMT_FLAGS){
		log_warning("pid %d flags change %x %x", pid, d->flags, PSI_PID_PMT_FLAGS);
		d->flags = PSI_PID_PMT_FLAGS;
	    }
	    d->pmt.program_number = MPEG_HILO(pat_prog->program_number);
	    /* do not touch data_hash on existing PMTs as it
	     * will force to re-read PMT
	     *
	     * this behavour can be used in future to garbage-collect
	     * stale PMTs (the ones with data_hash==0)
	     */
	    /* d->data_hash = 0; */
	}

	p_offs += PAT_PROG_LEN;
    }
}

static void mpeg_psi_sdt(THIS, uint8_t *data, int data_len)
{
    struct pid_descriptor *d;
    struct descriptor_hdr *descriptor_hdr;
    struct sdt_descr *sdt_descr;
    struct service_descriptor *service_descriptor;
    struct sdt *sdt;
    int sect_len;
    int dl_offs, dl_len;
    int s_offs, s_len;
    uint32_t crc;

    sdt = (void*)data;

    sect_len = MPEG_HILO(sdt->section_length);

    /* these checks are safe before crc validation:
     * if crc is ok - packed will be dropped
     * if crc is broken and conditions are true, packet will be dropped
     */

    if (sdt->current_next_indicator == 0){
	/* we are not interested in 'next' tables */
	return;
    }

    if (sdt->table_id != PSI_TABLE_ID_SDT){
	/* ignore other tables here */
	return;
    }

    if (sdt->version_number == this->sdt_version){
	/* this version parsed */
	return;
    }

    if (crc32_check(data, sect_len + SDT_LEN_FIX, CRC32_INIT)){
	log_warning("psi sdt crc error");
	return;
    }


    crc = *(uint32_t*)(&data[sect_len + SDT_LEN_FIX - MPEG_PSI_CRC_LEN]);


    d = psi_pid_lookup(this, MPEG_PID_SDT);

    if (d){
	/* new version */
	d->pid = MPEG_PID_SDT;
	d->flags = PSI_PID_SDT_FLAGS;
	d->data_hash = crc;
    } else {
	d = psi_pid_descriptor_alloc(this);

	d->pid = MPEG_PID_SDT;
	d->flags = PSI_PID_SDT_FLAGS;
	d->data_hash = crc;

	psi_pid_register(this, d);
    }

    log_info("SDT: table id: %d, len: %d, version: %d", sdt->table_id, MPEG_HILO(sdt->section_length),
		sdt->version_number);

    this->sdt_version = sdt->version_number;

    s_offs = 0;
    s_len = (sect_len+SDT_LEN_FIX) - (SDT_LEN+SDT_LEN_FIX+MPEG_PSI_CRC_LEN);

    while (s_offs < s_len) {
	sdt_descr = (void*)data + SDT_LEN + s_offs;

	log_info("\t service id: %d", MPEG_HILO(sdt_descr->service_id));

	dl_offs = 0;
	dl_len = MPEG_HILO(sdt_descr->descriptors_loop_length);
	while (dl_offs < dl_len) {
	    descriptor_hdr = (void*)sdt_descr + SDT_DESCR_LEN + dl_offs;
	    switch (descriptor_hdr->descriptor_tag){
		case descriptor_id_Service_Descriptor:{
		    int len;
		    service_descriptor = (struct service_descriptor*)descriptor_hdr;

		    len = SDT_service_provider_name_length(service_descriptor);
		    convert_dvb_string(SDT_service_provider_name(service_descriptor), len, this->current_provider_name, SDT_NAME_LEN);


		    len = SDT_service_name_length(service_descriptor);
		    convert_dvb_string(SDT_service_name(service_descriptor), len, this->current_service_name, SDT_NAME_LEN);


		    log_info("\t provider: '%s', name: '%s'", this->current_provider_name, this->current_service_name);

		    break;
		}
	    }
	    dl_offs += sizeof(struct descriptor_hdr) + descriptor_hdr->descriptor_length;
	}

	s_offs += SDT_DESCR_LEN + MPEG_HILO(sdt_descr->descriptors_loop_length);
    }

    this->sdt_mangle_serial++;
}

static void mpeg_psi_pmt(THIS, uint16_t pid, uint8_t *data, int data_len)
{
    struct pid_descriptor *d;
    struct pmt *pmt;
    struct pmt_info *pmt_info;
    struct descriptor_hdr *descriptor_hdr;
    int sect_len, pmti_offs, pmti_len;
    int desc_offs, desc_len;
    uint32_t crc;

    pmt = (struct pmt*)data;

    sect_len = MPEG_HILO(pmt->section_length);

    if (crc32_check(data, sect_len + PMT_LEN_FIX, CRC32_INIT)){
	log_warning("psi pmt crc error");
	return;
    }

    crc = *(uint32_t*)(&data[sect_len + PMT_LEN_FIX - MPEG_PSI_CRC_LEN]);

    if (pmt->table_id != PSI_TABLE_ID_PMT){
	log_warning("psi pmt invalid table_id: 0x%x", pmt->table_id);
	return;
    }

    d = psi_pid_lookup(this, pid);

    if (d){
	if ((d->flags == PSI_PID_PMT_FLAGS) && (d->pmt.version == pmt->version_number) &&
		(d->data_hash == crc)){
	    return;
	}
	d->pid = pid;
	d->flags = PSI_PID_PMT_FLAGS;
	d->data_hash = crc;
	d->pmt.version = pmt->version_number;
    } else {
	d = psi_pid_descriptor_alloc(this);

	d->pid = pid;
	d->flags = PSI_PID_PMT_FLAGS;
	d->data_hash = crc;
	d->pmt.version = pmt->version_number;

	psi_pid_register(this, d);
    }

    log_info("PMT: table_id: %d, len: %d, prog: %d, version: %d, "
	     "pcr_pid: 0x%04x, len: %d", pmt->table_id, MPEG_HILO(pmt->section_length),
		MPEG_HILO(pmt->program_number), pmt->version_number,
		MPEG_HILO(pmt->PCR_PID), MPEG_HILO(pmt->program_info_length));

    this->pmt_program_id = MPEG_HILO(pmt->program_number);

    pmti_offs = 0;
    pmti_len = MPEG_HILO(pmt->program_info_length);
    while (pmti_offs < pmti_len) {
	descriptor_hdr = (void*)data + PMT_LEN + pmti_offs;

	switch (descriptor_hdr->descriptor_tag){
	    case descriptor_id_CA:
		//register_descriptor_ecm(this, pmt, NULL, (void*)descriptor_hdr);
		break;
	    default:
		log_info("\t tag: 0x%02x, data: %*T", descriptor_hdr->descriptor_tag,
			descriptor_hdr->descriptor_length,
			((char*)descriptor_hdr) + sizeof(struct descriptor_hdr));
	}

	pmti_offs += sizeof(struct descriptor_hdr) + descriptor_hdr->descriptor_length;
    }

    pmti_offs = MPEG_HILO(pmt->program_info_length);
    pmti_len = sect_len + PMT_LEN_FIX - PMT_LEN - MPEG_PSI_CRC_LEN;

    while (pmti_offs < pmti_len) {
	pmt_info = (void*)data + PMT_LEN + pmti_offs;
	log_info("\t type: 0x%02x, pid: 0x%04x, len: %d", pmt_info->stream_type,
	    MPEG_HILO(pmt_info->elementary_PID),
	    MPEG_HILO(pmt_info->ES_info_length));

	d = psi_pid_lookup(this, MPEG_HILO(pmt_info->elementary_PID));
	if (d == NULL){
	    d = psi_pid_descriptor_alloc(this);

	    d->pid = MPEG_HILO(pmt_info->elementary_PID);
	    d->flags = PSI_PID_TYPE_PES;
	    d->data_hash = 0;

	    d->es.sid = MPEG_HILO(pmt->program_number);
	    d->es.type = pmt_info->stream_type;

	    psi_pid_register(this, d);
	} else {
	    d->flags = PSI_PID_TYPE_PES;
	    d->data_hash = 0;

	    d->es.sid = MPEG_HILO(pmt->program_number);
	    d->es.type = pmt_info->stream_type;
	}

	desc_offs = 0;
	desc_len = MPEG_HILO(pmt_info->ES_info_length);
	while (desc_offs < desc_len){
	    descriptor_hdr = (void*)pmt_info + PMT_INFO_LEN + desc_offs;
	    switch (descriptor_hdr->descriptor_tag){
		case descriptor_id_CA:
		    //register_descriptor_ecm(this, pmt, pmt_info, (void*)descriptor_hdr);
		    break;
		default:
		    log_info("\t\t tag: 0x%02x, data: %*T", descriptor_hdr->descriptor_tag,
			    descriptor_hdr->descriptor_length,
			    ((char*)descriptor_hdr) + sizeof(struct descriptor_hdr));
	    }
	    desc_offs += sizeof(struct descriptor_hdr) + descriptor_hdr->descriptor_length;
	}
	pmti_offs += PMT_INFO_LEN + MPEG_HILO(pmt_info->ES_info_length);
    }

}

