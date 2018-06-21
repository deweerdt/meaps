#include <unistd.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "meaps.h"

static int read_bio(BIO *b, char *out, int len)
{
    meaps_conn_t *conn = BIO_get_data(b);

    if (len == 0)
        return 0;

    return read(conn->fd, out, len);
}

static int write_bio(BIO *b, const char *in, int len)
{
    meaps_conn_t *conn = BIO_get_data(b);

    /* FIXME no support for SSL renegotiation (yet) */
    return write(conn->fd, in, len);
}

static int puts_bio(BIO *b, const char *str)
{
    return write_bio(b, str, (int)strlen(str));
}

static long ctrl_bio(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
        case BIO_CTRL_GET_CLOSE:
            return BIO_get_shutdown(b);
        case BIO_CTRL_SET_CLOSE:
            BIO_set_shutdown(b, (int)num);
            return 1;
        case BIO_CTRL_FLUSH:
            return 1;
        default:
            return 0;
    }
}

static void setup_bio(meaps_conn_t *conn)
{
    static BIO_METHOD *bio_methods = NULL;
    if (bio_methods == NULL) {
        static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&init_lock);
        if (bio_methods == NULL) {
            BIO_METHOD *biom = BIO_meth_new(BIO_TYPE_FD, "meaps_socket");
            BIO_meth_set_write(biom, write_bio);
            BIO_meth_set_read(biom, read_bio);
            BIO_meth_set_puts(biom, puts_bio);
            BIO_meth_set_ctrl(biom, ctrl_bio);
            __sync_synchronize();
            bio_methods = biom;
        }
        pthread_mutex_unlock(&init_lock);
    }

    BIO *bio = BIO_new(bio_methods);
    if (bio == NULL)
        meaps_fatal("no memory");
    BIO_set_data(bio, conn);
    BIO_set_init(bio, 1);
    SSL_set_bio(conn->ssl.ossl, bio, bio);
}

static void do_handshake(meaps_conn_t *conn, const char *err)
{
    static __thread char ssl_error[sizeof("-2147483648")];
    if (err != NULL) {
        conn->ssl.on_connect(conn, err);
        return;
    }
    int ret = SSL_connect(conn->ssl.ossl);
    if (ret > 0) {
        conn->ssl.on_connect(conn, NULL);
        return;
    }
    switch (ret = SSL_get_error(conn->ssl.ossl, ret)) {
    case SSL_ERROR_WANT_READ:
        conn->dont_read = 1;
        meaps_conn_wait_read(conn, do_handshake);
        return;
    case SSL_ERROR_WANT_WRITE:
        meaps_conn_wait_write(conn, do_handshake);
        return;
    default:
        snprintf(ssl_error, sizeof(ssl_error), "%d", ret);
        conn->cb(conn, ssl_error);
        return;
    }
}
void meaps_conn_ssl_do_handshake(meaps_conn_t *conn, meaps_conn_cb cb)
{
    conn->ssl.on_connect = cb;
    conn->state = SSL_HANDSHAKE;
    SSL_set_fd(conn->ssl.ossl, conn->fd);
    do_handshake(conn, NULL);
}

void meaps_conn_ssl_init(meaps_conn_t *conn, SSL_CTX *ctx)
{
    conn->ssl.ossl = SSL_new(ctx);
    setup_bio(conn);
}

