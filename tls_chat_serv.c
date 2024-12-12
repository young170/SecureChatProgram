#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 100
#define MAX_CLNT 256

void *handle_clnt(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *msg);

int clnt_cnt = 0;
SSL *clnt_ssl[MAX_CLNT];
pthread_mutex_t mutx;

SSL_CTX* init_ssl_context(const char* cert_file, const char* key_file) {
    SSL_CTX *ctx;

	// init openssl
    SSL_library_init(); // SSL_library_init() registers the available SSL/TLS ciphers and digests.
    OpenSSL_add_all_algorithms(); // OpenSSL_add_all_algorithms() adds all algorithms to the table (digests and ciphers).
    SSL_load_error_strings(); // SSL_load_error_strings() registers the error strings for all libcrypto functions, and also registers the libssl error strings.

	// init ssl context
    const SSL_METHOD *method = TLSv1_2_server_method(); // A TLS/SSL connection established with these methods will only understand the TLSv1.2 protocol.
    ctx = SSL_CTX_new(method); // SSL_CTX_new_() creates a new SSL_CTX object, which holds various configuration and data relevant to SSL/TLS or DTLS session establishment.
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // load certificate
	// SSL_CTX_use_certificate_file() loads the certificates into the SSL_CTX.
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// load private key
	// SSL_CTX_use_PrivateKey_file() loads the private keys into the SSL object.
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// verify private key
	// SSL_CTX_check_private_key() checks the consistency of a private key with the corresponding certificate loaded into ctx.
	if (SSL_CTX_check_private_key(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// SSL_CTX_set_verify() sets the verification flags for ctx to be mode and specifies the verify_callback function to be used.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	// SSL_CTX_load_verify_locations() specifies the locations for ctx.
    if (!SSL_CTX_load_verify_locations(ctx, "ca_cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void print_certs(SSL *ssl) {
	X509 *cert;
	char *line;

	// SSL_get_peer_certificate() return a pointer to the X509 certificate the peer presented.
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if (cert != NULL) {
		printf("Server certificates:\n");
		// X509_NAME_oneline() prints an ASCII version of X509_NAME to a buffer.
		// X509_get_subject_name() returns the subject name of certificate x.
		// X509_get_issuer_name() returns and sets the subject name of certificate x.
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		// X509_free() frees up the X509 structure.
		X509_free(cert);
	} else
		printf("No certificates.\n");
}

int main(int argc, char *argv[])
{
	int serv_sock, clnt_sock;
	struct sockaddr_in serv_adr, clnt_adr;
	int clnt_adr_sz;
	pthread_t t_id;
	SSL_CTX *ctx;

	if (argc != 4) {
		printf("Usage: %s <port> <cert-file> <key-file>\n", argv[0]);
		exit(1);
	}
  
	pthread_mutex_init(&mutx, NULL);

    ctx = init_ssl_context(argv[2], argv[3]);

	serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	memset(&serv_adr, 0, sizeof(serv_adr));
	serv_adr.sin_family = AF_INET; 
	serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_adr.sin_port = htons(atoi(argv[1]));
	
	if (bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr)) == -1)
		error_handling("bind() error");
	if (listen(serv_sock, 5) == -1)
		error_handling("listen() error");
	
	while (1)
	{
		clnt_adr_sz = sizeof(clnt_adr);
		clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr,&clnt_adr_sz);
		
		// SSL_new() create a new SSL structure for a connection
        SSL *ssl = SSL_new(ctx);
		if (!ssl) {
			ERR_print_errors_fp(stderr);
            close(clnt_sock);
            continue;
		}

		// SSL_set_fd() connect the SSL object with a file descriptor
        if (SSL_set_fd(ssl, clnt_sock) != 1) {
			ERR_print_errors_fp(stderr);
            close(clnt_sock);
            continue;
		}

		// SSL_accept() wait for a TLS/SSL client to initiate a TLS/SSL handshake
		if (SSL_accept(ssl) != 1) { // TLS handshake
            ERR_print_errors_fp(stderr);
            close(clnt_sock);
            continue;
        }
		printf("TLS/SSL handshake successful\n");
		// SSL_get_cipher() returns the stack of available SSL_CIPHERs for ssl, sorted by preference.
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		print_certs(ssl);

		pthread_mutex_lock(&mutx);
		clnt_ssl[clnt_cnt++] = ssl;
		pthread_mutex_unlock(&mutx);

		pthread_create(&t_id, NULL, handle_clnt, (void*)ssl);
		pthread_detach(t_id);
		printf("Connected client IP: %s \n", inet_ntoa(clnt_adr.sin_addr));
	}

	close(serv_sock);
	// SSL_CTX_free() decrements the reference count of ctx,
	// and removes the SSL_CTX object pointed to by ctx and frees up the allocated memory if the reference count has reached 0.
	SSL_CTX_free(ctx);
	return 0;
}
	
void *handle_clnt(void *arg)
{
	SSL *ssl = (SSL *)arg;
	int str_len = 0, i;
	char msg[BUF_SIZE];
	
	// SSL_read() try to read num bytes from the specified ssl into the buffer buf.
	while ((str_len = SSL_read(ssl, msg, sizeof(msg))) > 0) {
		send_msg(msg, str_len);
	}
	
	if (str_len < 0) {
		// SSL_get_error() returns a result code.
        int err = SSL_get_error(ssl, str_len);
        fprintf(stderr, "SSL_read error: %d\n", err);
    }

	pthread_mutex_lock(&mutx);
	for (i = 0; i < clnt_cnt; i++)   // remove disconnected client
	{
		if (ssl == clnt_ssl[i])
		{
			// SSL_shutdown() shuts down an active TLS/SSL connection.
			SSL_shutdown(clnt_ssl[i]);
			// SSL_free() decrements the reference count of ssl
			// and removes the SSL structure pointed to by ssl and frees up the allocated memory if the reference count has reached 0.
        	SSL_free(clnt_ssl[i]);

			while (i < clnt_cnt-1)
			{
				clnt_ssl[i] = clnt_ssl[i+1];
				i++;
			}
			break;
		}
	}
	clnt_cnt--;
	pthread_mutex_unlock(&mutx);
	return NULL;
}

void send_msg(char * msg, int len)   // send to all
{
	int i;
	pthread_mutex_lock(&mutx);
	for (i = 0; i < clnt_cnt; i++) {
		// SSL_write() write num bytes from the buffer buf into the specified ssl connection.
		if (SSL_write(clnt_ssl[i], msg, len) <= 0) {
			int err = SSL_get_error(clnt_ssl[i], len);
            fprintf(stderr, "SSL_write error: %d\n", err);
		}
	}
	pthread_mutex_unlock(&mutx);
}
void error_handling(char * msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}