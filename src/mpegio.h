#ifndef MPEGIO_H
#define MPEGIO_H

#include "global.h"

struct mpegio_stream;
struct mpegio_client;
typedef struct mpegio_stream *MPEGIO;
typedef void (*mpegeio_on_send_error)(void *param, uint32_t ssrc, int in_errno);

struct mpegio_config {
    /* this struct is used as a key to determine uniquness of a mpegio */
    /* make sure to memset(0) new structs for conistent results*/
    struct in_addr addr;
    uint16_t port;
    uint16_t __padding0;

    int __key_end;	// all data int this struct below this line is not part of a key

    int send_fd;
    int init_buf_size;
    int streaming_delay;

    mpegeio_on_send_error on_send_error;
    void *cbdata;
};

#define MPEGIO_KEY_SIZE (offsetof(struct mpegio_config, __key_end))

int mpegio_configure(MPEGIO _this, const struct mpegio_config *config);
MPEGIO mpegio_alloc();
int mpegio_init(MPEGIO);
int mpegio_is_initialized(MPEGIO);
void mpegio_free(MPEGIO);

struct mpegio_client *mpegio_client_create(MPEGIO, struct in_addr *dest, uint16_t port, uint32_t ssrc);

struct mpegio_client *mpegio_client_find_by_id(MPEGIO, int client_id);
int mpegio_client_get_parameters(MPEGIO, struct mpegio_client *client, int *id, uint32_t *ssrc, uint32_t *rtp_seq);
int mpegio_clientid_get_parameters(MPEGIO, int client_id, uint32_t *ssrc, uint32_t *rtp_seq);

int mpegio_client_send_error_notify(MPEGIO, struct mpegio_client *client);
int mpegio_client_set_active(MPEGIO, struct mpegio_client *client, int active);
int mpegio_clientid_set_active(MPEGIO, int client_id, int active);
int mpegio_clientid_destroy(MPEGIO, int client_id);

#endif /* MPEGIO_H */
