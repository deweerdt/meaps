#include <openssl/ssl.h>
#include <sys/epoll.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef struct st_meaps_iovec_t {
    char *base;
    size_t *len;
} meaps_iovec_t;

typedef struct st_meaps_header_t {
    meaps_iovec_t name;
    meaps_iovec_t value;
} meaps_header_t;

typedef struct st_meaps_url_t {
    meaps_iovec_t scheme;
    meaps_iovec_t host;
    uint16_t port;
    meaps_iovec_t path;
    meaps_iovec_t query_string;
} meaps_url_t;

typedef struct st_meaps_request_t {
    meaps_url_t url;
    meaps_header_t *headers;
} meaps_request_t;

typedef struct st_meaps_conn_t {
    int fd;
    SSL *ssl;
} meaps_conn_t;

typedef struct st_meaps_http1client_t {
    meaps_conn_t conn;
} meaps_http1client_t;
typedef struct st_meaps_loop_t {
    int epoll_fd;
} meaps_loop_t;


int meaps_run_loop(meaps_loop_t *loop, int timeout)
{
    int ret;
    struct epoll_event events[100];
    ret = epoll_wait(loop->epoll_fd, events, ARRAY_SIZE(events), timeout);
    if (ret < 0)
        return ret;
}

int main(void)
{

    return 0;
}
