#ifndef PSI_H
#define PSI_H

#include "global.h"
#include "mpeg_tbl.h"

#define PSI_PID_TYPE_MASK 0xf
#define PSI_PID_TYPE_PAT 0
#define PSI_PID_TYPE_CAT 1
#define PSI_PID_TYPE_SDT 2
#define PSI_PID_TYPE_PMT 3
#define PSI_PID_TYPE_ECM 4
#define PSI_PID_TYPE_EMM 5
#define PSI_PID_TYPE_PES 6
#define PSI_PID_TYPE_UNREF PSI_PID_TYPE_MASK

#define PSI_PID_NEEDS_REASSEMBLY 0x10

#define PSI_PID_TYPE(_f_) ((_f_) & PSI_PID_TYPE_MASK)

#define PSI_PID_PAT_FLAGS (PSI_PID_TYPE_PAT | PSI_PID_NEEDS_REASSEMBLY)
#define PSI_PID_CAT_FLAGS (PSI_PID_TYPE_CAT | PSI_PID_NEEDS_REASSEMBLY)
#define PSI_PID_SDT_FLAGS (PSI_PID_TYPE_SDT | PSI_PID_NEEDS_REASSEMBLY)
#define PSI_PID_PMT_FLAGS (PSI_PID_TYPE_PMT | PSI_PID_NEEDS_REASSEMBLY)

struct mpeg_psi;
struct pid_descriptor;

typedef struct mpeg_psi *PSI;

PSI psi_alloc();
int psi_init(PSI, const char *identifier);
void psi_cleanup(PSI);

int psi_pid_register(PSI, struct pid_descriptor *p);
struct pid_descriptor *psi_pid_lookup(PSI, uint16_t pid);
void psi_pids_flush(PSI);
int psi_pid_lookup_flags(PSI, uint16_t pid);

int psi_submit_for_reassemply(PSI, uint16_t pid, uint16_t flags, uint8_t *pkt);

#endif /* PSI_H */
