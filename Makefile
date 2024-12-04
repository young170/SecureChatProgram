CC = gcc
CFLAGS = -Wall -Wextra

SERVER_SRC = tls_chat_server.c
CLIENT_SRC = tls_chat_client.c

SERVER_BIN = tls_server
CLIENT_BIN = tls_client

ROOT_CERT_FILE = server_cert.pem
ROOT_KEY_FILE = server_key.pem
SERVER_REQUEST_FILE = server_csr.pem
SERVER_CERT_FILE = server_cert.pem
SERVER_KEY_FILE = server_key.pem
CLIENT_REQUEST_FILE = client_csr.pem
CLIENT_CERT_FILE = client_cert.pem
CLIENT_KEY_FILE = client_key.pem

.PHONY: all server client certs clean

all: server client

server: $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o $(SERVER_BIN) -lssl -lcrypto -lpthread

client: $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o $(CLIENT_BIN) -lssl -lcrypto -lpthread

certs:
	openssl genrsa -out ca_key.pem 2048
	openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 3650 -out ca_cert.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Org Unit/CN=RootCA"

	openssl genrsa -out server_key.pem 2048
	openssl req -new -key server_key.pem -out server_csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Org Unit/CN=Server"
	openssl x509 -req -in server_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out server_cert.pem -days 365 -sha256

	openssl genrsa -out client_key.pem 2048
	openssl req -new -key client_key.pem -out client_csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Org Unit/CN=Client"
	openssl x509 -req -in client_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 365 -sha256

	openssl verify -CAfile ca_cert.pem server_cert.pem
	openssl verify -CAfile ca_cert.pem client_cert.pem


clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN) $(ROOT_CERT_FILE) $(ROOT_KEY_FILE) \
	$(SERVER_REQUEST_FILE) $(SERVER_CERT_FILE) $(SERVER_KEY_FILE) $(CLIENT_REQUEST_FILE) $(CLIENT_CERT_FILE) $(CLIENT_KEY_FILE)
