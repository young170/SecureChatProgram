# Secure Chat Program
Computer Security-HW3
Seongbin Kim 22100113

### Description
TLS-based chat program secured using OpenSSL in C.
Clients first connect to the server. Then, clients "chat" messages or files to other clients via the server.
All messages (and files) are broadcasted to all clients from the server.
To send a file, the command, `file_share:<filename>`, must be used.

### Prerequisites
Versions tested on:
1. OpenSSL: `1.1.1f`
2. gcc: `(Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0`

### Build
```
# build both server and client
$ make

# build only `server` or `client`
$ make <server+client>

# create certificates and keys for server and client
$ make certs
```

### Run
1. Run server
```
$ ./tls_server <port> <server_certificate_filename> <server_key_filename>
$ ./tls_server 9000 server_cert.pem server_key.pem
```

2. Run client
```
$ ./tls_client <server_IP> <server_port> <client_name> <client_certificate_filename> <client_key_filename>
$ ./tls_client 172.17.0.1 9000 muadDib client_cert.pem client_key.pem

3. Start chat using client
$ <text>
$ file_share:<filename>
```

### Parameters
* `port`
  * server: port number to open
* `server_certificate_filename
  * filename of server's certificate
* `server_key_filename`
  * filename of server's key
* `server_IP`
  * IP number of server to connect to
* `server_port`
  * port number of server to connect to
* `client_name`
  * name of client
* `client_certificate_filename`
  * filename of client's certificate
* `client_key_filename`
  * filename of client's certificate
