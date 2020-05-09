#ifndef MEAPS_H_
#define MEAPS_H_

#include <stdlib.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include "picohttpparser.h"

#define container_of(ptr, type, member)                                                                                            \
    ({                                                                                                                             \
        const typeof(((type *)0)->member) *__mptr = (ptr);                                                                         \
        (type *)((char *)__mptr - offsetof(type, member));                                                                         \
    })

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

void meaps_conn_add_event(meaps_conn_t *conn, size_t len);
void meaps_conn_close(meaps_conn_t *conn);

/***/

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
void meaps_conn_ssl_init(meaps_conn_t *conn, SSL_CTX *ctx);

/***/

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
typedef struct st_meaps_iovec_t {
    char *base;
    size_t len;
} meaps_iovec_t;

#define MEAPS_IOVEC_STRLIT(s) meaps_iovec_init((s ""), sizeof(s) - 1)
#define MEAPS_IOVEC_STR(s) meaps_iovec_init((s), strlen(s))

meaps_iovec_t meaps_buffer_get_iovec(meaps_buffer_t *buf);
static inline meaps_iovec_t meaps_iovec_init(char *base, size_t len)
{
    return (meaps_iovec_t){base, len};
}

/***/

enum meaps_url_scheme_t { HTTP, HTTPS };
typedef struct st_meaps_url_t {
    struct {
        meaps_iovec_t scheme;
        meaps_iovec_t host;
        meaps_iovec_t path;
        meaps_iovec_t port;
    } raw;
    struct {
        enum meaps_url_scheme_t scheme;
        uint16_t port;
    } parsed;
} meaps_url_t;

void meaps_url_parse(meaps_iovec_t to_parse, meaps_url_t *url, const char **err);

/***/

typedef struct st_meaps_header_t {
    meaps_iovec_t name;
    meaps_iovec_t value;
} meaps_header_t;

/***/

typedef struct st_meaps_request_t {
    meaps_iovec_t method;
    meaps_url_t url;
    meaps_header_t *headers;
    size_t nr_headers;
    struct {
        int minor_version, status;
        meaps_iovec_t msg;
        struct phr_header headers[100];
        size_t nr_headers;
        size_t content_length;
        int is_chunked;
        int keep_alive;
        meaps_buffer_t body;
        struct phr_chunked_decoder chunked_decoder;
    } res;
} meaps_request_t;

void meaps_request_add_header(meaps_request_t *req, meaps_iovec_t name, meaps_iovec_t value);
void meaps_request_dispose(meaps_request_t *req);

/***/

typedef struct st_meaps_loop_t {
    int epoll_fd;
    int stop;
} meaps_loop_t;

meaps_loop_t *meaps_loop_create(void);
int meaps_loop_run(meaps_loop_t *loop, int timeout);
void meaps_loop_destroy(meaps_loop_t *loop);

/***/

struct st_meaps_http1client_t;
typedef void (*meaps_http1client_cb)(struct st_meaps_http1client_t *, const char *);
typedef struct st_meaps_http1client_t {
    meaps_loop_t *loop;
    meaps_conn_t conn;
    meaps_request_t *req;
    struct sockaddr_storage ss_dst;
    union {
        meaps_http1client_cb on_connect;
        meaps_http1client_cb on_request_sent;
        meaps_http1client_cb on_response_head;
        meaps_http1client_cb on_response_body;
    };
    int done;
} meaps_http1client_t;

meaps_http1client_t *meaps_http1client_create(meaps_loop_t *loop);
void meaps_http1client_close(meaps_http1client_t *client);
void meaps_http1client_connect(meaps_http1client_t *client, meaps_http1client_cb on_connect_cb,
                               struct sockaddr_storage *ss_override);
void meaps_http1client_read_response_body(meaps_http1client_t *client, meaps_http1client_cb on_response_body, int closed);
void meaps_http1client_read_response_head(meaps_http1client_t *client, meaps_http1client_cb on_response_head);
void meaps_http1client_write_request(meaps_http1client_t *client, meaps_request_t *req, meaps_http1client_cb on_request_sent_cb);

/***/

extern const char meaps_err_connection_error[];
extern const char meaps_err_invalid_url[];
extern const char meaps_err_connection_closed[];
extern const char meaps_err_connection_closed_prematurely[];
extern const char meaps_err_io_error[];
extern const char meaps_err_url_is_empty[];
extern const char meaps_err_unknown_scheme[];
extern const char meaps_err_url_scheme_unrecognized[];
extern const char meaps_err_url_invalid_port[];
extern const char meaps_err_url_invalid_chars_after_authority[];

#endif /* MEAPS_H_ */
