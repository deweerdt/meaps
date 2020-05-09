#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>

#include "meaps.h"
#include "meaps_ssl.h"

struct st_meaps_conn_t;

meaps_iovec_t meaps_iovec_dup(char *base, size_t len)
{
    meaps_iovec_t iov = {meaps_alloc(len), len};
    memcpy(iov.base, base, len);
    return iov;
}

/***/

const char meaps_err_connection_error[] = "connection error";
const char meaps_err_invalid_url[] = "invalid url";
const char meaps_err_connection_closed[] = "connection closed";
const char meaps_err_connection_closed_prematurely[] = "connection closed prematurely";
const char meaps_err_io_error[] = "I/O error";

/***/

const char meaps_err_url_is_empty[] = "Empty URL";
const char meaps_err_unknown_scheme[] = "Unknown scheme";
const char meaps_err_url_scheme_unrecognized[] = "Unrecognized scheme in URL";
const char meaps_err_url_invalid_port[] = "Invalid port in URL";
const char meaps_err_url_invalid_chars_after_authority[] = "Invalid chars after authority in URL";

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
            url->parsed.scheme = HTTPS;
        } else if (url->raw.scheme.len == 4 && memmem("http", 4, url->raw.scheme.base, url->raw.scheme.len)) {
            uport = 80; /* may be overriden later */
            url->parsed.scheme = HTTP;
        } else {
            *err = meaps_err_unknown_scheme;
            return;
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
            url->raw.host.len = i - start_host;
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
void meaps_url_to_port(meaps_url_t *url, struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) {
        ((struct sockaddr_in *)ss)->sin_port = htons(url->parsed.port);
    } else {
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(url->parsed.port);
    }
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
            break;
        }
    }
    freeaddrinfo(res);
    return ret;
}

/***/

void meaps_buffer_init(meaps_buffer_t *buf)
{
    memset(buf, 0, sizeof(*buf));
}

void meaps_buffer_expand(meaps_buffer_t *buf, size_t len)
{
    size_t new_cap = buf->cap ? buf->cap : 4096;
    while (len + buf->len > new_cap) {
        new_cap *= 2;
    }
    buf->base = meaps_realloc(buf->base, new_cap);
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

void meaps_buffer_destroy(meaps_buffer_t *buf)
{
    free(buf->base);
}

meaps_iovec_t meaps_buffer_get_iovec(meaps_buffer_t *buf)
{
    return meaps_iovec_init(buf->base + buf->idx, buf->len - buf->idx);
}

/***/

void meaps_request_add_header(meaps_request_t *req, meaps_iovec_t name, meaps_iovec_t value)
{
    req->headers = meaps_realloc(req->headers, sizeof(*req->headers) * (req->nr_headers + 1));
    req->headers[req->nr_headers].name = name;
    req->headers[req->nr_headers].value = value;
    req->nr_headers++;
    return;
}

void meaps_request_dispose(meaps_request_t *req)
{
    free(req->headers);
    meaps_buffer_destroy(&req->res.body);
}

/***/

const char *meaps_event_type(meaps_event_type_t type)
{
    const char *etxt[] = {
        [START] = "START",
        [DNS] = "DNS",
        [SSL_HANDSHAKE] = "SSL_HANDSHAKE",
        [CONNECT] = "CONNECT",
        [READ_HEAD] = "READ_HEAD",
        [READ_BODY] = "READ_BODY",
        [WRITE_HEAD] = "WRITE_HEAD",
        [WRITE_BODY] = "WRITE_BODY",
        [CLOSE] = "CLOSE",
    };
    if (type >= ARRAY_SIZE(etxt))
        return "unknown event type";
    return etxt[type];
}
void meaps_conn_add_event(meaps_conn_t *conn, size_t len)
{
    meaps_event_t *e = meaps_alloc(sizeof(*e));
    e->type = conn->state;
    clock_gettime(CLOCK_MONOTONIC, &e->t);
    e->len = len;
    e->next = conn->events;
    conn->events = e;
    return;
}

void meaps_loop_wait_read(struct st_meaps_loop_t *loop, struct st_meaps_conn_t *conn);
void meaps_loop_wait_write(struct st_meaps_loop_t *loop, struct st_meaps_conn_t *conn);

ssize_t meaps_conn_read_impl(meaps_conn_t *conn)
{
    ssize_t rret, total_read = 0;
    if (conn->ssl.ossl == NULL) {
        while (1) {
            meaps_buffer_expand(&conn->rbuffer, 16834);
            while ((rret = read(conn->fd, conn->rbuffer.base + conn->rbuffer.len, conn->rbuffer.cap - conn->rbuffer.len)) == -1 &&
                   errno == EINTR)
                ;
            if (rret < 0) {
                if (errno != EAGAIN) {
                    conn->cb(conn, "read error");
                    break;
                }
                break;
            } else if (rret == 0) {
                meaps_conn_add_event(conn, 0);
                break;
            }
            conn->rbuffer.len += rret;
            total_read += rret;
        }
        if (rret == 0) {
            conn->cb(conn, meaps_err_connection_closed);
        } else {
            conn->cb(conn, NULL);
        }
        return total_read;
    } else {
        while (1) {
            int ret;
            static __thread char ssl_error[sizeof("-2147483648")];
            meaps_buffer_expand(&conn->rbuffer, 16834);
            rret = SSL_read(conn->ssl.ossl, conn->rbuffer.base + conn->rbuffer.len, conn->rbuffer.cap - conn->rbuffer.len);
            if (rret > 0) {
                conn->rbuffer.len += rret;
                total_read += rret;
                continue;
            }
            switch (ret = SSL_get_error(conn->ssl.ossl, rret)) {
            case SSL_ERROR_WANT_READ:
                if (total_read > 0) {
                    conn->cb(conn, NULL);
                } else {
                    meaps_loop_wait_read(conn->loop, conn);
                }
                return total_read;
            case SSL_ERROR_WANT_WRITE:
                meaps_loop_wait_write(conn->loop, conn);
                return total_read;
            case SSL_ERROR_ZERO_RETURN:
                conn->cb(conn, meaps_err_connection_closed);
                return total_read;
            default:
                snprintf(ssl_error, sizeof(ssl_error), "%d", ret);
                conn->cb(conn, ssl_error);
                return -1;
            }
        }
    }
}

ssize_t meaps_conn_write_impl(meaps_conn_t *conn)
{
    ssize_t wret, total_written = 0;
    meaps_iovec_t iov;

    if (conn->ssl.ossl == NULL) {
        while (!meaps_buffer_empty(&conn->wbuffer)) {
            iov = meaps_buffer_get_iovec(&conn->wbuffer);
            while ((wret = write(conn->fd, iov.base, iov.len)) == -1 && errno == EINTR)
                ;
            if (wret < 0) {
                if (errno != EAGAIN) {
                    conn->cb(conn, strerror(errno));
                    return -1;
                }
                meaps_loop_wait_write(conn->loop, conn);
                return total_written;
            }
            total_written += wret;
            meaps_buffer_consume(&conn->wbuffer, wret);
        }
        assert(meaps_buffer_empty(&conn->wbuffer));
        conn->cb(conn, NULL);
        return total_written;
    } else {
        while (!meaps_buffer_empty(&conn->wbuffer)) {
            iov = meaps_buffer_get_iovec(&conn->wbuffer);
            wret = SSL_write(conn->ssl.ossl, iov.base, (int)iov.len);
            if (wret <= 0) {
                int ret;
                static __thread char ssl_error[sizeof("-2147483648")];
                switch (ret = SSL_get_error(conn->ssl.ossl, wret)) {
                case SSL_ERROR_WANT_READ:
                    meaps_loop_wait_read(conn->loop, conn);
                    return total_written;
                case SSL_ERROR_WANT_WRITE:
                    meaps_loop_wait_write(conn->loop, conn);
                    return total_written;
                case SSL_ERROR_ZERO_RETURN:
                    conn->cb(conn, meaps_err_connection_closed);
                    return total_written;
                default:
                    snprintf(ssl_error, sizeof(ssl_error), "%d", ret);
                    conn->cb(conn, ssl_error);
                    return -1;
                }
            }
            total_written += wret;
            meaps_buffer_consume(&conn->wbuffer, wret);
        }
        assert(meaps_buffer_empty(&conn->wbuffer));
        conn->cb(conn, NULL);
        return total_written;
    }
}

void meaps_conn_wait_write(meaps_conn_t *conn, meaps_conn_cb cb)
{
    conn->cb = cb;
    if (conn->ssl.ossl != NULL)
        conn->ssl.state = MEAPS_SSL_WRITING;
    meaps_loop_wait_write(conn->loop, conn);
}

void meaps_conn_wait_read(meaps_conn_t *conn, meaps_conn_cb cb)
{
    conn->cb = cb;
    if (conn->ssl.ossl != NULL)
        conn->ssl.state = MEAPS_SSL_READING;
    meaps_loop_wait_read(conn->loop, conn);
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
    int s, ret, one = 1;

    s = socket(ss->ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s < 0) {
        cb(conn, meaps_err_connection_error);
        return;
    }
    ret = connect(s, (struct sockaddr *)ss, sizeof_ss(ss));
    if (ret < 0 && errno != EINPROGRESS) {
        cb(conn, meaps_err_connection_error);
    }
    setsockopt(s, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
    conn->fd = s;
    conn->loop = loop;
    meaps_buffer_init(&conn->wbuffer);
    meaps_buffer_init(&conn->rbuffer);
    meaps_conn_wait_write(conn, cb);
}

void meaps_conn_close(meaps_conn_t *conn)
{
    meaps_event_t *e, *next;
    e = conn->events;
    while (e) {
        next = e->next;
        free(e);
        e = next;
    }
    close(conn->fd);
    meaps_buffer_destroy(&conn->wbuffer);
    meaps_buffer_destroy(&conn->rbuffer);
    if (conn->ssl.ossl) {
        SSL_free(conn->ssl.ossl);
    }
    conn->fd = -1;
}

/***/

meaps_loop_t *meaps_loop_create(void)
{
    meaps_loop_t *loop;
    int efd;
    efd = epoll_create(10);
    if (efd < 0)
        return NULL;
    loop = meaps_alloc(sizeof(*loop));
    loop->epoll_fd = efd;
    loop->stop = 0;
    return loop;
}

void meaps_loop_destroy(meaps_loop_t *loop)
{
    close(loop->epoll_fd);
    free(loop);
}

void meaps_loop_wait_write(meaps_loop_t *loop, struct st_meaps_conn_t *conn)
{
    int ret;
    struct epoll_event e = {.events = EPOLLOUT, .data.ptr = conn};
    ret = epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, conn->fd, &e);
    assert(ret == 0 && "epoll_ctl failed");
}

void meaps_loop_wait_read(meaps_loop_t *loop, struct st_meaps_conn_t *conn)
{
    int ret;
    struct epoll_event e = {.events = EPOLLIN, .data.ptr = conn};
    ret = epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, conn->fd, &e);
    if (conn->ssl.ossl != NULL)
        conn->ssl.state = MEAPS_SSL_READING;
    assert(ret == 0 && "epoll_ctl failed");
}

void meaps_conn_read(meaps_conn_t *conn, meaps_conn_cb cb)
{
    conn->cb = cb;
    meaps_loop_wait_read(conn->loop, conn);
}

int meaps_loop_run(meaps_loop_t *loop, int timeout)
{
    int ret, n;
    struct epoll_event events[100];
    ssize_t total_read = 0, total_written = 0;
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
            if (conn->dont_read) {
                conn->dont_read = 0;
                conn->cb(conn, NULL);
                continue;
            }
        reading:
            if (conn->ssl.ossl != NULL && conn->ssl.state == MEAPS_SSL_WRITING)
                goto writing;
            total_read = meaps_conn_read_impl(conn);
            meaps_conn_add_event(conn, total_read);
        }
        if (events[n].events & EPOLLOUT) {
        writing:
            if (conn->ssl.ossl != NULL && conn->ssl.state == MEAPS_SSL_READING)
                goto reading;
            total_written = meaps_conn_write_impl(conn);
            meaps_conn_add_event(conn, total_written);
        }
    }
    return 0;
}

/***/

meaps_http1client_t *meaps_http1client_create(meaps_loop_t *loop)
{
    meaps_http1client_t *client;
    client = calloc(1, sizeof(*client));
    client->loop = loop;
    return client;
}

void meaps_http1client_on_connect(meaps_conn_t *conn, const char *err)
{
    meaps_http1client_t *client = container_of(conn, meaps_http1client_t, conn);
    client->on_connect(client, err);
}

void meaps_http1client_request_sent(meaps_conn_t *conn, const char *err)
{
    meaps_http1client_t *client = container_of(conn, meaps_http1client_t, conn);
    client->on_request_sent(client, err);
}

void meaps_http1client_connect(meaps_http1client_t *client, meaps_http1client_cb on_connect_cb,
                               struct sockaddr_storage *ss_override)
{
    client->conn.state = START;

    /* dns resolution */
    if (ss_override == NULL) {
        meaps_conn_add_event(&client->conn, 0);
        client->conn.state = DNS;
        if (!meaps_url_to_sockaddr(&client->req->url, &client->ss_dst)) {
            on_connect_cb(client, meaps_err_invalid_url);
            return;
        }
        meaps_conn_add_event(&client->conn, 0);
    } else {
        client->ss_dst = *ss_override;
    }
    meaps_url_to_port(&client->req->url, &client->ss_dst);
    client->on_connect = on_connect_cb;
    client->conn.state = CONNECT;
    meaps_conn_connect(&client->conn, client->loop, &client->ss_dst, meaps_http1client_on_connect);
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
    client->conn.state = WRITE_HEAD;
    meaps_conn_wait_write(&client->conn, meaps_http1client_request_sent);
}

ssize_t parse_content_length(const char *base, size_t len)
{
    ssize_t ret = 0;
    const char *end = base + len;
    while (base < end && isspace(*base)) {
        base++;
    }
    while (base < end) {
        if (*base < '0' || *base > '9')
            return -1;
        ret = ret * 10 + *base - '0';
        base++;
    }
    return ret;
}

void on_read_head(meaps_conn_t *conn, const char *err)
{
    meaps_iovec_t iov;
    int pret;
    meaps_http1client_t *client = container_of(conn, meaps_http1client_t, conn);
    meaps_request_t *req;

    if (err != NULL && err != meaps_err_connection_closed) {
        goto out;
    }

    req = client->req;
    iov = meaps_buffer_get_iovec(&client->conn.rbuffer);
    req->res.nr_headers = ARRAY_SIZE(req->res.headers);
    pret = phr_parse_response(iov.base, iov.len, &req->res.minor_version, &req->res.status, (const char **)&req->res.msg.base,
                              &req->res.msg.len, req->res.headers, &req->res.nr_headers, 0);
    if (pret == -1) {
        err = "failed to parse response";
        goto out;
    }

    if (pret == -2) {
        if (err == meaps_err_connection_closed) {
            err = meaps_err_connection_closed_prematurely;
            goto out;
        }
        meaps_conn_read(conn, on_read_head);
        return;
    }

    req->res.content_length = SIZE_MAX;
    req->res.is_chunked = 0;
    req->res.keep_alive = 1;
    meaps_buffer_init(&req->res.body);
    int transfer_encoding_seen = 0, content_length_seen = 0;
    for (int i = 0; i < req->res.nr_headers; i++) {
        if (!strncasecmp(req->res.headers[i].name, "content-length", req->res.headers[i].name_len)) {
            ssize_t cl;
            if (content_length_seen) {
                err = "two content-length headers seen";
                goto out;
            }
            content_length_seen = 1;
            cl = parse_content_length(req->res.headers[i].value, req->res.headers[i].value_len);
            if (cl < 0) {
                err = "invalid content-length: header";
                goto out;
            }
            req->res.content_length = cl;
        } else if (!strncasecmp(req->res.headers[i].name, "transfer-encoding", req->res.headers[i].name_len)) {
            if (transfer_encoding_seen) {
                err = "two transfer-encoding headers seen";
                goto out;
            }
            transfer_encoding_seen = 1;
            if (!strncasecmp(req->res.headers[i].value, "chunked", req->res.headers[i].value_len)) {
                req->res.is_chunked = 1;
                memset(&req->res.chunked_decoder, 0, sizeof(req->res.chunked_decoder));
            }
        } else if (!strncasecmp(req->res.headers[i].name, "connection", req->res.headers[i].name_len)) {
            if (!strncasecmp(req->res.headers[i].value, "close", req->res.headers[i].value_len)) {
                req->res.keep_alive = 0;
            }
        }
    }
    // fprintf(stderr, "cl: %zu, chunked: %d, ka: %d\n", req->res.content_length, req->res.is_chunked, req->res.keep_alive);

    meaps_buffer_consume(&client->conn.rbuffer, pret);
out:
    client->on_response_head(client, err);
}

void meaps_http1client_read_response_head(meaps_http1client_t *client, meaps_http1client_cb on_response_head)
{
    client->on_response_head = on_response_head;
    client->conn.state = READ_HEAD;
    meaps_conn_read(&client->conn, on_read_head);
}

void on_read_body(meaps_conn_t *conn, const char *err)
{
    meaps_iovec_t iov;
    meaps_http1client_t *client = container_of(conn, meaps_http1client_t, conn);

    if (client->req->res.content_length != SIZE_MAX) {
        iov = meaps_buffer_get_iovec(&conn->rbuffer);
        if (iov.len != client->req->res.content_length)
            goto read_more;
        meaps_buffer_write(&client->req->res.body, iov.base, iov.len);
        meaps_buffer_consume(&conn->rbuffer, iov.len);
        client->on_response_body(client, NULL);
        return;

    } else if (!client->req->res.is_chunked) {
        /* connection close */
        assert(client->req->res.keep_alive == 0);
        if (err == NULL)
            goto read_more;
        if (err == meaps_err_connection_closed) {
            client->on_response_body(client, NULL);
        } else {
            client->on_response_body(client, err);
        }
        return;
    } else {
        ssize_t ret;
        size_t before_len;
        iov = meaps_buffer_get_iovec(&conn->rbuffer);
        before_len = iov.len;
        ret = phr_decode_chunked(&client->req->res.chunked_decoder, iov.base, &iov.len);
        if (ret == -1) {
            client->on_response_body(client, "chunked decoding failed");
            return;
        }
        meaps_buffer_write(&client->req->res.body, iov.base, iov.len);
        if (ret == -2) {
            meaps_buffer_consume(&conn->rbuffer, before_len);
            goto read_more;
        }
        client->on_response_body(client, NULL);
        return;
    }
read_more:
    meaps_conn_read(&client->conn, on_read_body);
    return;
}

void meaps_http1client_read_response_body(meaps_http1client_t *client, meaps_http1client_cb on_response_body, int closed)
{
    client->on_response_body = on_response_body;
    client->conn.state = READ_BODY;
    if (!meaps_buffer_empty(&client->conn.rbuffer)) {
        meaps_conn_add_event(&client->conn, client->conn.rbuffer.len);
        on_read_body(&client->conn, closed ? meaps_err_connection_closed : NULL);
    } else {
        meaps_conn_read(&client->conn, on_read_body);
    }
}

struct timespec ts_difftime(struct timespec start, struct timespec end)
{
    struct timespec ret;

    if ((end.tv_nsec - start.tv_nsec) < 0) {
        ret.tv_sec = end.tv_sec - start.tv_sec - 1;
        ret.tv_nsec = end.tv_nsec - start.tv_nsec + 1000000000;
    } else {
        ret.tv_sec = end.tv_sec - start.tv_sec;
        ret.tv_nsec = end.tv_nsec - start.tv_nsec;
    }

    return ret;
}

void meaps_http1client_close(meaps_http1client_t *client)
{
    meaps_event_t *e;
    int nr_events = 0, i = 0;

    if (client->conn.events != NULL) {
        e = client->conn.events;
        while (e) {
            nr_events++;
            e = e->next;
        }

        meaps_event_t evts[nr_events];
        e = client->conn.events;
        i = 0;
        while (e) {
            evts[nr_events - i - 1] = *e;
            e = e->next;
            i++;
        }

        meaps_event_t prev = evts[0];
        for (i = 1; i < nr_events; i++) {
            struct timespec tdiff;
            e = &evts[i];
            tdiff = ts_difftime(prev.t, e->t);
            prev = *e;
            fprintf(stderr, "event: %s, at %ld, bytes:%zu\n", meaps_event_type(e->type),
                    (tdiff.tv_sec * 1000) + tdiff.tv_nsec / 1000000, e->len);
        }
    }
    client->done = 1;
}

