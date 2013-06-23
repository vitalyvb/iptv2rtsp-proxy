#ifndef MPEGIO_H
#define MPEGIO_H

#include "global.h"

struct mpegio_stream;
struct mpegio_client;
typedef struct mpegio_stream *MPEGIO;

/* Error handler callbacks.
 * Warning: callback must not change mpegio clients list.
 *          Calling mpegio_clientid_destroy() will break things.
 */
typedef void (*mpegeio_rtp_on_send_error)(void *param, uint32_t ssrc, int in_errno);
typedef void (*mpegeio_fd_on_send_error)(void *param, int fd, uint64_t fd_param, int in_errno);

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

    mpegeio_rtp_on_send_error rtp_on_send_error;
    mpegeio_fd_on_send_error fd_on_send_error;
    void *cbdata;
};

#define MPEGIO_KEY_SIZE (offsetof(struct mpegio_config, __key_end))

#define MPEGIO_CLIENT_RELEASE (-1)
#define MPEGIO_CLIENT_STOP (0)
#define MPEGIO_CLIENT_PLAY (1)

#define IS_MPEGIO_CLIENT_ACTIVE(_s_) ((_s_)>0)

int mpegio_configure(MPEGIO _this, const struct mpegio_config *config);
MPEGIO mpegio_alloc();
int mpegio_init(MPEGIO);
int mpegio_is_initialized(MPEGIO);
void mpegio_free(MPEGIO);

struct mpegio_client *mpegio_client_create(MPEGIO);
int mpegio_client_setup_rtp(struct mpegio_client *client, struct in_addr *dest, uint16_t port, uint32_t ssrc);
int mpegio_client_setup_fd(struct mpegio_client *client, int fd, uint64_t fd_param);

struct mpegio_client *mpegio_client_find_by_id(MPEGIO, int client_id);
int mpegio_client_get_parameters(MPEGIO, struct mpegio_client *client, int *id, uint32_t *ssrc, uint32_t *rtp_seq);
int mpegio_clientid_get_parameters(MPEGIO, int client_id, uint32_t *ssrc, uint32_t *rtp_seq);

int mpegio_client_send_error_notify(MPEGIO, struct mpegio_client *client);
int mpegio_client_set_status(MPEGIO, struct mpegio_client *client, int status);
int mpegio_clientid_set_status(MPEGIO, int client_id, int status);
int mpegio_clientid_destroy(MPEGIO, int client_id);

#endif /* MPEGIO_H */
