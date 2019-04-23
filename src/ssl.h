#ifndef SSL_H
#define SSL_H


#include <stdint.h>
#include <s2n.h>
#include "ae.h"
#include <openssl/ssl.h>
#include "adlist.h"

#define SSL_ENABLE_DEFAULT 0

#define SSL_CIPHER_PREFS_DEFAULT "default"

struct client;
struct s2n_connection;

typedef enum {
    NEGOTIATE_NOT_STARTED = 0, NEGOTIATE_RETRY, NEGOTIATE_DONE, NEGOTIATE_FAILED
} SslNegotiationStatus;

#define SSL_PERFORMANCE_MODE_LOW_LATENCY 0
#define SSL_PERFORMANCE_MODE_HIGH_THROUGHPUT 1
#define SSL_PERFORMANCE_MODE_DEFAULT SSL_PERFORMANCE_MODE_LOW_LATENCY
#define DER_CERT_LEN_BYTES 3
#define CERT_VALIDATION_IGNORE_EXPIRED_CERTS 1
#define CERT_VALIDATION_IGNORE_SELF_SIGNED_CERTS  0
#define CERT_CNAME_MAX_LENGTH 256
#define CERT_DATE_MAX_LENGTH 256
//default value of root-ca-certs-path parameter.
#define ROOT_CA_CERTS_PATH "/etc/ssl/certs/ca-bundle.crt"

typedef struct
{
    X509_STORE * trust_store;
    char *expected_hostname;
} client_cert_verify_context;

#define NEWLINE_PING_IN_PROGRESS_FLAG (1<<0)
#define LOAD_NOTIFICATION_SENT_FLAG (1<<1)
#define CLIENT_CONNECTION_FLAG (1<<2)
#define OLD_CERTIFICATE_FLAG (1<<3)

/* Our internal representation of an SSL connection */
typedef struct ssl_connection {

    /* S2N connection reference */
    struct s2n_connection* s2nconn;

    /* File descriptor for the SSL connection */
    int fd;

    /* An int containing references to flags */
    int connection_flags;
    /* NEWLINE_PING_IN_PROGRESS_FLAG: Is a newline ping in progress (from a call to sslPing())?  1 if true, 0 otherwise. */
    /* LOAD_NOTIFICATION_SENT_FLAG: Has the load notification character been sent to the master */
    /* CLIENT_CONNECTION_FLAG: Is this connection associated with a redis client */
    /* OLD_CERTIFICATE_FLAG: Is this connection associated with an older certificate */

    /* Does the S2N connection contain cached data?  Set to a list node (present in
     * sslconn_with_cached_data list) if true, NULL otherwise. */
    listNode *cached_data_node;

} ssl_connection;

/* Structure to store SSL related information */
typedef struct {

    int enable_ssl; /* Controls whether SSL is enabled or not*/

    struct s2n_config *server_ssl_config; /* Structure to store S2N configuration like certificate, diffie-hellman parameters, cipher suite preferences */

    time_t server_ssl_config_creation_time; /* Creation time of SSL configuration */

    char *ssl_certificate; /* SSL certificate for SSL */

    char *ssl_certificate_file; /* File containing SSL certificate for SSL */

    char *ssl_certificate_private_key; /* private key corresponding to SSL certificate*/

    char *ssl_certificate_private_key_file; /* File containing private key corresponding to SSL certificate*/

    char *ssl_dh_params; /* DH parameters for SSL*/

    char *ssl_dh_params_file; /* File containing DH parameters for SSL*/

    char *ssl_cipher_prefs; /* Cipher preferences for SSL */

    int ssl_performance_mode; /* SSL performance mode - low latency or high throughput */

    struct s2n_config *client_ssl_config; /* Structure to store s2n configuration for replication */

    ssl_connection **fd_to_sslconn; /* socket fd to SSL connection mapping */

    unsigned int fd_to_sslconn_size; /* current size of fd_to_sslconn mapping */

    struct s2n_config *server_ssl_config_old; /* SSL configuration corresponding to expired/expiring certificate */

    client_cert_verify_context *client_cert_verify_context; /* Context for certification verification in clients */

    char *root_ca_certs_path; /* Path to root CA certificates */

    list *sslconn_with_cached_data; /* A list of SSL connections which contain cached data, which will be drained by repeated read task. */

    long long repeated_reads_task_id; /* The ae task ID of the timer event to process repeated reads, or -1 if not set. */

    uint64_t total_repeated_reads; /* Total number of repeated reads performed since the process began. */

    unsigned long max_repeated_read_list_length; /* The maximum number of repeated reads processed simultaneously. */

    char * expected_hostname; /* Expected hostname used for verifying ssl connections */

    char * certificate_not_before_date; /* The not before date on the latest ssl certificate */

    char * certificate_not_after_date; /* The not after date on the latest ssl certificate */

    long certificate_serial; /* The serial of the certificate, this should be converted to hex before displaying */

    int connections_to_previous_certificate; /* The number of connections that connected to the old certificate */ 

    int connections_to_current_certificate; /* The number of connections that connected to the new certificate */
} ssl_t;

// SSL Primitive functions
ssize_t sslRead(int fd, void *buffer, size_t nbytes);

ssize_t sslWrite(int fd, const void *buffer, size_t nbytes);

void sslPing(int fd);

const char *sslstrerror(void);

// SSL configuration functions
void initSsl(ssl_t *ssl);

void cleanupSsl(ssl_t *ssl);

void initSslConfigDefaults(ssl_t *ssl_config);

int isResizeAllowed(ssl_connection **fd_to_ssl_conn, int cur_size, int new_size);

int resizeFdToSslConnSize(ssl_t *ssl, unsigned int setsize);

int renewCertificate(char *new_certificate, char *new_private_key, char *new_certificate_filename,
    char *new_private_key_filename);

void deleteReadEventHandlerForSlavesWaitingBgsave();

// SSL helper functions
int getSslPerformanceModeByName(char *name);

char *getSslPerformanceModeStr(int mode);

// SSL connection functions
ssl_connection *
initSslConnection(s2n_mode connection_mode, struct s2n_config *config, int fd, int ssl_performance_mode, char *masterhost,
               ssl_connection **fd_to_sslconn, int fd_to_sslconn_size);

int setupSslOnClient(struct client *c, int fd, int ssl_performance_mode, ssl_connection **fd_to_sslconn,
                        int fd_to_sslconn_size);

int cleanupSslConnectionForFd(int fd);

int cleanupSslConnectionForFdWithoutShutdown(int fd);

// SSL Negotiation functions
void sslNegotiateWithClient(aeEventLoop *el, int fd, void *privdata, int mask);

void sslNegotiateWithMaster(aeEventLoop *el, int fd, void *privdata, int mask);

void syncWithMaster(aeEventLoop *el, int fd, void *privdata, int mask);

void sslNegotiateWithClusterNodeAsServer(aeEventLoop *el, int fd, void *privdata, int mask);

void sslNegotiateWithClusterNodeAsClient(aeEventLoop *el, int fd, void *privdata, int mask);

void startSslNegotiateWithMasterAfterRdbLoad(int fd);

void startSslNegotiateWithSlaveAfterRdbTransfer(struct client *slave);

void startWaitForSlaveToLoadRdbAfterRdbTransfer(struct client *slave);

int syncSslNegotiateForFd(int fd, long timeout);

#endif //SSL_H