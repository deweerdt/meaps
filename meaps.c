#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/types.h>

struct st_meaps_conn_t;

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef struct st_meaps_iovec_t {
    char *base;
    size_t len;
} meaps_iovec_t;

#define MEAPS_IOVEC_STRLIT(s) meaps_iovec_init((s ""), sizeof(s) - 1)
#define MEAPS_IOVEC_STR(s) meaps_iovec_init((s), strlen(s))

meaps_iovec_t meaps_iovec_init(char *base, size_t len)
{
    return (meaps_iovec_t){ base, len };
}

typedef struct st_meaps_header_t {
    meaps_iovec_t name;
    meaps_iovec_t value;
} meaps_header_t;

/***/

enum meaps_url_scheme_t {
    HTTP,
    HTTPS
};
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

const char *meaps_err_url_is_empty = "Empty URL";
const char *meaps_err_url_scheme_unrecognized = "Unrecognized scheme in URL";
const char *meaps_err_url_invalid_port = "Invalid port in URL";
const char *meaps_err_url_invalid_chars_after_authority = "Invalid chars after authority in URL";

void meaps_url_parse(meaps_iovec_t to_parse, meaps_url_t *url, const char **err)
{
    int i, start_host;
    bool found_scheme = false;
    unsigned int uport = 0;

    memset(url, 0, sizeof(*url));
    if (!to_parse.len) {
        *err = meaps_err_url_is_empty;
        return;
    }
    if (!isalpha(to_parse.base[0])) {
        *err = meaps_err_url_scheme_unrecognized;
        return;
    }
    for (i = 1; i < to_parse.len && to_parse.base[i] != ':'; i++) {
        if (!isalpha(to_parse.base[i]) && !isdigit(to_parse.base[i]) && to_parse.base[i] != '+' && to_parse.base[i] != '-' &&
            to_parse.base[i] != '.') {
            url->raw.scheme.base = NULL;
            url->raw.scheme.len = 0;
            goto no_scheme;
        }
    }
    if (i + 2 >= to_parse.len || to_parse.base[i + 1] != '/' || to_parse.base[i + 2] != '/') {
        goto no_scheme;
    }
    found_scheme = true;

no_scheme:
    if (found_scheme) {
        url->raw.scheme.base = &to_parse.base[0];
        url->raw.scheme.len = i;
        i += 3;
        if (url->raw.scheme.len == 5 && memmem("https", 5, url->raw.scheme.base, url->raw.scheme.len)) {
            uport = 443; /* may be overriden later */
        } else if (url->raw.scheme.len == 4 && memmem("http", 4, url->raw.scheme.base, url->raw.scheme.len)) {
            uport = 80; /* may be overriden later */
        }
    } else {
        url->raw.scheme.base = NULL;
        url->raw.scheme.len = 0;
        i = 0;
    }

    start_host = i;
    url->raw.host.base = &to_parse.base[i];
    url->raw.host.len = 0;

    for (; i < to_parse.len; i++) {
        if (to_parse.base[i] == ':') {
            url->raw.host.len = i - start_host;
            url->raw.port.base = &to_parse.base[i + 1];
            uport = 0;
            for (i = i + 1; i < to_parse.len; i++) {
                if (!isdigit(to_parse.base[i])) {
                    break;
                }
                uport = uport * 10 + (to_parse.base[i] - '0');
                if (uport > 0xffff) {
                    *err = meaps_err_url_invalid_port;
                    return;
                }
            }
            url->raw.port.len = &to_parse.base[i] - url->raw.port.base;
            break;
        } else if (to_parse.base[i] == '/') {
            url->raw.host.len = i;
            url->raw.path.base = &to_parse.base[i];
            url->raw.path.len = to_parse.len - i;
            break;
        }
    }
    if (i == to_parse.len && !url->raw.host.len) {
        url->raw.host.len = i - start_host;
    }
    if (i != to_parse.len && to_parse.base[i] != '/') {
        *err = meaps_err_url_invalid_chars_after_authority;
        return;
    }
    url->parsed.port = (uint16_t)uport;
    return;
}

int meaps_url_to_sockaddr(meaps_url_t *url, struct sockaddr_storage *ss)
{
    int ret = 0;
    struct addrinfo hints;
    char host[url->raw.host.len + 1];
    struct addrinfo *res = NULL, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    memcpy(host, url->raw.host.base, url->raw.host.len);
    host[url->raw.host.len] = '\0';

    ret = getaddrinfo(host, NULL, &hints, &res);
    if (ret != 0)
        return 0;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
            ret = 1;
            memcpy(ss, rp->ai_addr, rp->ai_addrlen);
            if (rp->ai_family == AF_INET) {
                ((struct sockaddr_in *)ss)->sin_port = htons(url->parsed.port);
            } else {
                ((struct sockaddr_in6 *)ss)->sin6_port = htons(url->parsed.port);
            }
            break;
        }
    }
    freeaddrinfo(res);
    return ret;
}

/***/

typedef struct st_meaps_request_t {
    meaps_iovec_t method;
    meaps_url_t url;
    meaps_header_t *headers;
    size_t nr_headers;
} meaps_request_t;

void meaps_request_add_header(meaps_request_t *req, meaps_iovec_t name, meaps_iovec_t value)
{
    req->headers = realloc(req->headers, sizeof(*req->headers) * (req->nr_headers + 1));
    req->headers[req->nr_headers].name = name;
    req->headers[req->nr_headers].value = value;
    req->nr_headers++;
    return;
}

/***/

typedef struct st_meaps_buffer_t {
    char *base;
    size_t idx;
    size_t len;
    size_t cap;
} meaps_buffer_t;

void meaps_buffer_init(meaps_buffer_t *buf)
{
    memset(buf, 0, sizeof(*buf));
}

void meaps_buffer_expand(meaps_buffer_t *buf, size_t len)
{
    size_t new_cap = buf->cap ? buf->cap : 4096;
    while (len > (new_cap - buf->len)) {
        new_cap *= 2;
    }
    buf->base = realloc(buf->base, new_cap);
    assert(buf->base != NULL);
    buf->cap = new_cap;
}

void meaps_buffer_write(meaps_buffer_t *buf, char *src, size_t len)
{
    meaps_buffer_expand(buf, len);
    memcpy(&buf->base[buf->len], src, len);
    buf->len += len;
}

void meaps_buffer_consume(meaps_buffer_t *buf, size_t len)
{
    assert(buf->idx + len < buf->cap);
    buf->idx += len;
}

int meaps_buffer_empty(meaps_buffer_t *buf)
{
    return buf->len == buf->idx;
}

meaps_iovec_t meaps_buffer_get_iovec(meaps_buffer_t *buf)
{
    return meaps_iovec_init(&buf->base[buf->idx], buf->len - buf->idx);
}
/***/

typedef void (*meaps_conn_cb)(struct st_meaps_conn_t *, const char *);
typedef void (*meaps_conn_io_cb)(struct st_meaps_conn_t *, meaps_conn_cb);
struct st_meaps_loop_t;
typedef struct st_meaps_conn_t {
    int fd;
    SSL *ssl;
    meaps_conn_cb cb;
    struct st_meaps_loop_t *loop;
    meaps_buffer_t wbuffer;
    meaps_buffer_t rbuffer;
} meaps_conn_t;

const char *meaps_err_connection_error = "connection error";
const char *meaps_err_invalid_url = "invalid url";
const char *meaps_err_connection_closed = "connection closed";
const char *meaps_err_io_error = "I/O error";

void meaps_loop_wait_write(struct st_meaps_loop_t *loop, struct st_meaps_conn_t *conn);
void meaps_conn_wait_write(meaps_conn_t *conn, meaps_conn_cb cb)
{
    conn->cb = cb;
    meaps_loop_wait_write(conn->loop, conn);
}

size_t sizeof_ss(struct sockaddr_storage *ss)
{
    switch (ss->ss_family) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        default:
            abort();
    }
}

void meaps_conn_connect(meaps_conn_t *conn, struct st_meaps_loop_t *loop, struct sockaddr_storage *ss, meaps_conn_cb cb)
{
    int s, ret;

    s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s < 0) {
        cb(conn, meaps_err_connection_error);
        return;
    }
    ret = connect(s, (struct sockaddr *)ss, sizeof_ss(ss));
    if (ret < 0 && errno != EINPROGRESS) {
        cb(conn, meaps_err_connection_error);
    }
    conn->fd = s;
    conn->loop = loop;
    meaps_buffer_init(&conn->wbuffer);
    meaps_buffer_init(&conn->rbuffer);
    meaps_conn_wait_write(conn, cb);
}

/***/

typedef struct st_meaps_loop_t {
    int epoll_fd;
    int stop;
} meaps_loop_t;


meaps_loop_t *meaps_loop_create(void)
{
    meaps_loop_t *loop;
    int efd;
    efd = epoll_create(10);
    if (efd < 0)
        return NULL;
    loop = malloc(sizeof(*loop));
    loop->epoll_fd = efd;
    loop->stop = 0;
    return loop;

}
void meaps_loop_wait_write(meaps_loop_t *loop, struct st_meaps_conn_t *conn)
{
    int ret;
    struct epoll_event e = { .events = EPOLLOUT, .data.ptr = conn };
    ret = epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, conn->fd, &e);
    assert(ret == 0 && "epoll_ctl failed");
}

void meaps_conn_read(meaps_conn_t *conn, meaps_conn_cb cb)
{
    int ret;
    struct epoll_event e = { .events = EPOLLIN, .data.ptr = conn };
    ret = epoll_ctl(conn->loop->epoll_fd, EPOLL_CTL_ADD, conn->fd, &e);
    assert(ret == 0 && "epoll_ctl failed");
    conn->cb = cb;
}

int meaps_loop_run(meaps_loop_t *loop, int timeout)
{
    int ret, n;
    struct epoll_event events[100];
    ret = epoll_wait(loop->epoll_fd, events, ARRAY_SIZE(events), timeout);
    if (ret < 0) {
        return ret;
    }
    for (n = 0; n < ret; ++n) {
        int eret;
        meaps_conn_t *conn = events[n].data.ptr;
        eret = epoll_ctl(loop->epoll_fd, EPOLL_CTL_DEL, conn->fd, 0);
        assert(eret == 0);
        if (events[n].events & EPOLLHUP) {
            conn->cb(conn, "connection closed");
            continue;
        }
        if (events[n].events & EPOLLERR) {
            conn->cb(conn, "IO error");
            continue;
        }
        if (events[n].events & EPOLLIN) {
            while (1) {
                ssize_t rret;
                meaps_buffer_expand(&conn->rbuffer, 4096);
                while ((rret = read(conn->fd, conn->rbuffer.base + conn->rbuffer.len, conn->rbuffer.cap)) == -1 && errno == EINTR)
                        ;
                if (rret < 0) {
                    if (errno != EAGAIN) {
                        conn->cb(conn, "read error");
                        continue;
                    }
                    break;
                }
                conn->rbuffer.len += rret;
            }
            conn->cb(conn, NULL);
        }
        if (events[n].events & EPOLLOUT) {
            ssize_t wret;
            meaps_iovec_t iov;

            while (!meaps_buffer_empty(&conn->wbuffer)) {
                iov = meaps_buffer_get_iovec(&conn->wbuffer);
                while ((wret = write(conn->fd, iov.base, iov.len)) == -1 && errno == EINTR)
                    ;
                if (wret < 0) {
                    if (errno != EAGAIN) {
                        conn->cb(conn, strerror(errno));
                        continue;
                    }
                    meaps_loop_wait_write(conn->loop, conn);
                    continue;
                }
                meaps_buffer_consume(&conn->wbuffer, wret);
            }
            assert(meaps_buffer_empty(&conn->wbuffer));
            conn->cb(conn, NULL);
        }
    }
    return 0;
}

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
    };
} meaps_http1client_t;

meaps_http1client_t *meaps_http1client_create(meaps_loop_t *loop)
{
    meaps_http1client_t *h1client;
    h1client = calloc(1, sizeof(*h1client));
    h1client->loop = loop;
    return h1client;
}


#define container_of(ptr, type, member) ({          \
            const typeof(((type *)0)->member)*__mptr = (ptr);    \
                         (type *)((char *)__mptr - offsetof(type, member)); })

void meaps_http1client_on_connect(meaps_conn_t *conn, const char *err)
{
    meaps_http1client_t *h1client = container_of(conn, meaps_http1client_t, conn);
    h1client->on_connect(h1client, err);
}

void meaps_http1client_request_sent(meaps_conn_t *conn, const char *err)
{
    meaps_http1client_t *h1client = container_of(conn, meaps_http1client_t, conn);
    h1client->on_request_sent(h1client, err);
}

void meaps_http1client_connect(meaps_http1client_t *h1client, meaps_url_t *url, meaps_http1client_cb on_connect_cb)
{
    if (!meaps_url_to_sockaddr(url, &h1client->ss_dst)) {
        on_connect_cb(h1client, meaps_err_invalid_url);
        return;
    }
    h1client->on_connect = on_connect_cb;
    meaps_conn_connect(&h1client->conn, h1client->loop, &h1client->ss_dst, meaps_http1client_on_connect);
}

#define CRLF "\r\n"

void meaps_http1client_write_request(meaps_http1client_t *client, meaps_request_t *req, meaps_http1client_cb on_request_sent_cb)
{
    size_t i;
    client->on_request_sent = on_request_sent_cb;
    meaps_buffer_write(&client->conn.wbuffer, req->method.base, req->method.len);
    meaps_buffer_write(&client->conn.wbuffer, " ", 1);
    if (req->url.raw.path.len == 0)
        meaps_buffer_write(&client->conn.wbuffer, "/", 1);
    else
        meaps_buffer_write(&client->conn.wbuffer, req->url.raw.path.base, req->url.raw.path.len);
    meaps_buffer_write(&client->conn.wbuffer, " ", 1);
    meaps_buffer_write(&client->conn.wbuffer, "HTTP/1.1", 8);
    meaps_buffer_write(&client->conn.wbuffer, CRLF, 2);

    for (i = 0; i < req->nr_headers; i++) {
        meaps_buffer_write(&client->conn.wbuffer, req->headers[i].name.base, req->headers[i].name.len);
        meaps_buffer_write(&client->conn.wbuffer, ": ", 2);
        meaps_buffer_write(&client->conn.wbuffer, req->headers[i].value.base, req->headers[i].value.len);
        meaps_buffer_write(&client->conn.wbuffer, CRLF, 2);
    }
    meaps_buffer_write(&client->conn.wbuffer, CRLF, 2);
    meaps_conn_wait_write(&client->conn, meaps_http1client_request_sent);
}

void on_read_head(meaps_conn_t *conn, const char *err)
{
    meaps_http1client_t *h1client = container_of(conn, meaps_http1client_t, conn);
    h1client->on_response_head(h1client, err);

}

void meaps_http1client_read_response(meaps_http1client_t *client, meaps_http1client_cb on_response_head)
{
    client->on_response_head = on_response_head;
    meaps_conn_read(&client->conn, on_read_head);
}

/***/

void on_response_head(meaps_http1client_t *client, const char *err)
{
    meaps_iovec_t iov;
    if (err == NULL) {
        iov = meaps_buffer_get_iovec(&client->conn.rbuffer);
        fprintf(stderr, "got: %.*s\n", (int)iov.len, iov.base);
    } else {
        fprintf(stderr, "err: %s\n", err);
    }
}

void on_request_written(meaps_http1client_t *client, const char *err)
{
    meaps_http1client_read_response(client, on_response_head);
}

void on_connect(meaps_http1client_t *client, const char *err)
{
    meaps_http1client_write_request(client, client->req, on_request_written);
}

int main(int argc, char **argv)
{
    const char *err = NULL;
    meaps_loop_t *loop = meaps_loop_create();
    meaps_request_t req;
    meaps_http1client_t *h1client = meaps_http1client_create(loop);
    meaps_url_t url;
    char *to_parse = argv[1] ? argv[1] : "http://yay.im";
    meaps_url_parse(MEAPS_IOVEC_STR(to_parse), &url, &err);
    if (err != NULL) {
        fprintf(stderr, "Failed to parse url: %s\n", to_parse);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.method = MEAPS_IOVEC_STRLIT("GET");
    meaps_request_add_header(&req, MEAPS_IOVEC_STRLIT("host"), MEAPS_IOVEC_STRLIT("yay.im"));
    h1client->req = &req;
    meaps_http1client_connect(h1client, &url, on_connect);

    while (!loop->stop && meaps_loop_run(loop, 10) >= 0)
        ;
    return 0;
}
