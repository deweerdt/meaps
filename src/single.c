#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "meaps.h"

static int verbose = 1;

static void on_response_body(meaps_http1client_t *client, const char *err)
{
    if (err) {
        fprintf(stderr, "Failed to read body: %s\n", err);
    } else {
        meaps_iovec_t body = meaps_buffer_get_iovec(&client->req->res.body);
        if (0) {
            fprintf(stderr, "%.*s\n", (int)body.len, body.base);
        }
    }
    meaps_http1client_close(client);
}

static void on_response_head(meaps_http1client_t *client, const char *err)
{
    if (err != NULL && err != meaps_err_connection_closed) {
        fprintf(stderr, "Error reading headers: %s\n", err);
        return;
    }

    if (verbose) {
        fprintf(stderr, "< HTTP/1.%d %d %.*s\n", client->req->res.minor_version, client->req->res.status,
                (int)client->req->res.msg.len, client->req->res.msg.base);
        for (int i = 0; i < client->req->res.nr_headers; i++) {
            struct phr_header *h = &client->req->res.headers[i];
            fprintf(stderr, "< %.*s: %.*s\n", (int)h->name_len, h->name, (int)h->value_len, h->value);
        }
    }

    if ((err == meaps_err_connection_closed && client->req->res.keep_alive == 0) || client->req->res.content_length == 0) {
        meaps_http1client_close(client);
        return;
    }

    meaps_http1client_read_response_body(client, on_response_body, err == meaps_err_connection_closed);
}

static void on_request_written(meaps_http1client_t *client, const char *err)
{
    if (err != NULL) {
        fprintf(stderr, "connection failed: %s, %s\n", err, strerror(errno));
        client->conn.loop->stop = 1;
        meaps_http1client_close(client);
        return;
    }
    meaps_http1client_read_response_head(client, on_response_head);
}

static void on_ssl_connect(meaps_conn_t *conn, const char *err)
{
    meaps_http1client_t *client = container_of(conn, meaps_http1client_t, conn);
    if (err != NULL) {
        fprintf(stderr, "connection failed: %s, %s\n", err, strerror(errno));
        meaps_http1client_close(client);
        return;
    }
    meaps_http1client_write_request(client, client->req, on_request_written);
}

static void on_connect(meaps_http1client_t *client, const char *err)
{
    meaps_conn_add_event(&client->conn, 0);
    if (err != NULL) {
        fprintf(stderr, "connection failed: %s, %s\n", err, strerror(errno));
        meaps_http1client_close(client);
        return;
    }
    if (client->conn.ssl.ossl != NULL) {
        meaps_conn_ssl_do_handshake(&client->conn, on_ssl_connect);
        return;
    }
    meaps_http1client_write_request(client, client->req, on_request_written);
}

static void usage(const char *progname)
{
    fprintf(stderr, "usage: %s [--force-ip <ip>] [--header <header name>:<header value>] url\n", progname);
}

int main(int argc, char **argv)
{
    const char *err = NULL;
    meaps_loop_t *loop = meaps_loop_create();
    meaps_request_t req;
    meaps_http1client_t *client = meaps_http1client_create(loop);
    char *progname = *argv;
    char *url_arg = NULL;
    struct sockaddr_storage ss, *ss_override = NULL;
    meaps_header_t *to_add = NULL;
    int i, nr_to_add = 0;
    SSL_CTX *ssl_ctx = NULL;

    argv++;
    if (*argv == NULL)
        goto usage;

    while (*argv) {
        if (!strcmp("--force-ip", *argv)) {
            unsigned char buf[sizeof(struct in6_addr)];
            memset(&ss, 0, sizeof(ss));
            argv++;
            if (*argv == NULL) {
                fprintf(stderr, "Missing argument for `--force-ip`\n");
                goto usage;
            }
            if (inet_pton(AF_INET, *argv, buf)) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
                sin->sin_family = AF_INET;
                memcpy(&sin->sin_addr, buf, sizeof(sin->sin_addr));
            } else if (inet_pton(AF_INET6, *argv, buf)) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
                sin6->sin6_family = AF_INET6;
                memcpy(&sin6->sin6_addr, buf, sizeof(sin6->sin6_addr));
            } else {
                fprintf(stderr, "Invalid IP address for `--force-ip`: %s\n", *argv);
                return 1;
            }
            ss_override = &ss;
            argv++;
        } else if (!strcmp("--header", *argv)) {
            argv++;
            if (*argv == NULL) {
                fprintf(stderr, "Missing argument for `--header`\n");
                goto usage;
            }

            char *colon = strchr(*argv, ':');
            if (colon == NULL) {
                fprintf(stderr, "A header must contain a value separated by a colon `:`\n");
                goto usage;
            }
            *colon = '\0';
            to_add = meaps_realloc(to_add, sizeof(*to_add) * (nr_to_add + 1));
            meaps_header_t *h = &to_add[nr_to_add];
            h->name = meaps_iovec_init(*argv, strlen(*argv));
            h->value = meaps_iovec_init(colon + 1, strlen(colon + 1));
            nr_to_add++;
            argv++;
        } else {
            url_arg = *argv++;
            if (*argv != NULL) {
                goto usage;
            }
            break;
        }
    }
    if (!url_arg) {
        goto usage;
    }

    memset(&req, 0, sizeof(req));
    meaps_url_parse(MEAPS_IOVEC_STR(url_arg), &req.url, &err);
    if (err != NULL) {
        fprintf(stderr, "Failed to parse url: %s\n", url_arg);
        return 1;
    }
    req.method = MEAPS_IOVEC_STRLIT("GET");
    meaps_request_add_header(&req, MEAPS_IOVEC_STRLIT("host"), req.url.raw.host);
    for (i = 0; i < nr_to_add; i++) {
        meaps_request_add_header(&req, to_add[i].name, to_add[i].value);
    }
    free(to_add);
    client->req = &req;
    if (req.url.parsed.scheme == HTTPS) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        meaps_conn_ssl_init(&client->conn, ssl_ctx);
    }
    meaps_http1client_connect(client, on_connect, ss_override);

    while (meaps_loop_run(loop, 10) >= 0) {
        if (client->done)
            break;
    }
    meaps_conn_close(&client->conn);
    meaps_loop_destroy(loop);
    meaps_request_dispose(&req);
    free(client);
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    return 0;
usage:
    usage(progname);
    return 1;
}
