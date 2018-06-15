static void setup_bio(h2o_socket_t *sock)
{
    static BIO_METHOD *bio_methods = NULL;
    if (bio_methods == NULL) {
        static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&init_lock);
        if (bio_methods == NULL) {
            BIO_METHOD *biom = BIO_meth_new(BIO_TYPE_FD, "h2o_socket");
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
        h2o_fatal("no memory");
    BIO_set_data(bio, sock);
    BIO_set_init(bio, 1);
    SSL_set_bio(sock->ssl->ossl, bio, bio);
}
