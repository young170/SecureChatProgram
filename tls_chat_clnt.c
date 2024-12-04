#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 100
#define NAME_SIZE 20
	
void *send_msg(void *arg);
void *recv_msg(void *arg);
void error_handling(char *msg);
	
char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE];

SSL_CTX *init_ssl_context(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx;

    // init openssl
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // init ssl context
    const SSL_METHOD *method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

	// load certificates
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// load private keys
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// verify private key
	if (SSL_CTX_check_private_key(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

    return ctx;
}

int main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_in serv_addr;
	SSL_CTX *ctx;
    SSL *ssl;
	pthread_t snd_thread, rcv_thread;
	void *thread_return;

	if (argc != 6) {
		printf("Usage : %s <IP> <port> <name> <cert-file> <key-file>\n", argv[0]);
		exit(1);
	}
	
	sprintf(name, "[%s]", argv[3]);

    ctx = init_ssl_context(argv[4], argv[5]);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));
	  
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
		error_handling("connect() error");
	
	// Wrap the socket with SSL
    ssl = SSL_new(ctx);
	if (!ssl) {
		ERR_print_errors_fp(stderr);
		close(sock);
		exit(1);
	}

    if (SSL_set_fd(ssl, sock) != 1) {
		ERR_print_errors_fp(stderr);
		close(sock);
		exit(1);
	}

    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

	pthread_create(&snd_thread, NULL, send_msg, (void*)ssl);
	pthread_create(&rcv_thread, NULL, recv_msg, (void*)ssl);
	pthread_join(snd_thread, &thread_return);
	pthread_join(rcv_thread, &thread_return);
	
	SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

	return 0;
}
	
void *send_msg(void *arg)   // send thread main
{
	SSL *ssl = (SSL *)arg;
	char name_msg[NAME_SIZE+BUF_SIZE];
	char filename[BUF_SIZE];
	char *ptr;

	while (1) 
	{
		fgets(msg, BUF_SIZE, stdin);
		
		if (!strcmp(msg,"q\n") || !strcmp(msg,"Q\n")) {
			SSL_shutdown(ssl);
    		SSL_free(ssl);
			exit(0);
		} else if ((ptr = strstr(msg, "file_share:"))) {
			strncpy(filename, ptr + strlen("file_share:"), BUF_SIZE - 1);
			filename[strlen(filename) - 1] = '\0';
			printf("[DEBUG] send_msg() filename: %s\n", filename);
			
			FILE *fp = fopen(filename, "rb");
            if (fp == NULL) {
                printf("[ERROR] File not found: %s\n", filename);
                continue;
            }

			sprintf(name_msg, "FILE:%s", filename);
			if (SSL_write(ssl, name_msg, strlen(name_msg)) <= 0) {
				ERR_print_errors_fp(stderr);
				exit(EXIT_FAILURE);
			}

			char file_buffer[BUF_SIZE];
            int bytes_read;
            while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), fp)) > 0) {
                int sent_bytes = 0;
                while (sent_bytes < bytes_read) {
                    int len = SSL_write(ssl, file_buffer + sent_bytes, bytes_read - sent_bytes);
                    if (len <= 0) {
                        printf("[ERROR] SSL_write failed\n");
                        fclose(fp);
                        return NULL;
                    }
                    sent_bytes += len;
                }
            }
            fclose(fp);
            printf("[DEBUG] File sent: %s\n", filename);
		} else {
			sprintf(name_msg,"%s %s", name, msg);
			if (SSL_write(ssl, name_msg, strlen(name_msg)) <= 0) {
				ERR_print_errors_fp(stderr);
				exit(EXIT_FAILURE);
			}
		}
	}
	return NULL;
}
	
void *recv_msg(void * arg)   // read thread main
{
	SSL *ssl = (SSL *)arg;
	int sock = *((int *)arg);
	char name_msg[NAME_SIZE+BUF_SIZE];
	int str_len;
	char filename[BUF_SIZE];
	char *ptr;

	while (1)
	{
		str_len = SSL_read(ssl, name_msg, NAME_SIZE + BUF_SIZE - 1);
		if (str_len <= -1) 
			return (void *) -1;

		name_msg[str_len] = '\0';
		char *ptr;

		if ((ptr = strstr(name_msg, "FILE:"))) {
			strncpy(filename, ptr + strlen("FILE:"), BUF_SIZE - 1);
			filename[strlen(filename) + 1] = '\0';
			printf("[DEBUG] recv_msg() filename: %s\n", filename);
			
			FILE *fp = fopen(filename, "wb");
            if (fp == NULL) {
                printf("[ERROR] File not found: %s\n", filename);
                continue;
            }

			char file_buffer[BUF_SIZE];
            int bytes_read;
            while ((bytes_read = SSL_read(ssl, file_buffer, sizeof(file_buffer))) > 0) {
                fwrite(file_buffer, 1, bytes_read, fp);
				
				if (bytes_read < BUF_SIZE)
					break;
            }

			if (bytes_read <= 0) {
				int err = SSL_get_error(ssl, bytes_read);
				fprintf(stderr, "SSL_read error: %d\n", err);
			}

            fclose(fp);
            printf("[DEBUG] File sent: %s\n", filename);
		} else {
			fputs(name_msg, stdout);
		}
	}
	return NULL;
}

void error_handling(char *msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}
