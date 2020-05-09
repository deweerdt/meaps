#ifndef MEAPS_H_
#define MEAPS_H_

#include <stdlib.h>
#include <openssl/ssl.h>

static inline void meaps_fatal(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    abort();
}

static inline void *meaps_alloc(size_t size)
{
    void *ret = malloc(size);
    if (ret == NULL)
        meaps_fatal("no memory");
    return ret;
}

static inline void *meaps_realloc(void *ptr, size_t size)
{
    void *ret = realloc(ptr, size);
    if (ret == NULL)
        meaps_fatal("no memory");
    return ret;
}

struct st_meaps_loop_t;
struct st_meaps_event_t;
struct st_meaps_conn_t;

typedef enum {
    START,
    DNS,
    SSL_HANDSHAKE,
    CONNECT,
    READ_HEAD,
    READ_BODY,
    WRITE_HEAD,
    WRITE_BODY,
    CLOSE,
} meaps_event_type_t;

typedef struct st_meaps_buffer_t {
    char *base;
    size_t idx;
    size_t len;
    size_t cap;
} meaps_buffer_t;

typedef enum {
    MEAPS_SSL_WRITING,
    MEAPS_SSL_READING,
} meaps_conn_ssl_state_t;

typedef void (*meaps_conn_cb)(struct st_meaps_conn_t *, const char *);
typedef struct st_meaps_conn_t {
    int fd;
    struct {
        SSL *ossl;
        meaps_conn_ssl_state_t state;
        meaps_conn_cb on_connect;
    } ssl;
    meaps_conn_cb cb;
    struct st_meaps_loop_t *loop;
    meaps_buffer_t wbuffer;
    meaps_buffer_t rbuffer;
    struct st_meaps_event_t *events;
    meaps_event_type_t state;
    int dont_read;
} meaps_conn_t;

typedef struct st_meaps_event_t {
    meaps_event_type_t type;
    struct timespec t;
    size_t len;
    struct st_meaps_event_t *next;
} meaps_event_t;

/***/

void meaps_conn_wait_write(meaps_conn_t *conn, meaps_conn_cb cb);
void meaps_conn_wait_read(meaps_conn_t *conn, meaps_conn_cb cb);

/***/

void meaps_conn_ssl_do_handshake(meaps_conn_t *conn, meaps_conn_cb cb);

#endif /* MEAPS_H_ */