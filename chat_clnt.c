#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
	
#define BUF_SIZE 100
#define NAME_SIZE 20
	
void *send_msg(void * arg);
void *recv_msg(void * arg);
void error_handling(char * msg);
	
char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE];
	
int main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_in serv_addr;
	pthread_t snd_thread, rcv_thread;
	void * thread_return;
	if (argc != 4) {
		printf("Usage : %s <IP> <port> <name>\n", argv[0]);
		exit(1);
	 }
	
	sprintf(name, "[%s]", argv[3]);
	sock = socket(PF_INET, SOCK_STREAM, 0);
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));
	  
	if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
		error_handling("connect() error");
	
	pthread_create(&snd_thread, NULL, send_msg, (void*)&sock);
	pthread_create(&rcv_thread, NULL, recv_msg, (void*)&sock);
	pthread_join(snd_thread, &thread_return);
	pthread_join(rcv_thread, &thread_return);
	close(sock);  
	return 0;
}
	
void *send_msg(void * arg)   // send thread main
{
	int sock = *((int*)arg);
	char name_msg[NAME_SIZE+BUF_SIZE];
	char filename[BUF_SIZE];
	char *ptr;

	while (1) 
	{
		fgets(msg, BUF_SIZE, stdin);
		
		if (!strcmp(msg,"q\n") || !strcmp(msg,"Q\n")) {
			close(sock);
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
            write(sock, name_msg, strlen(name_msg));

			char file_buffer[BUF_SIZE];
            int bytes_read;
            while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), fp)) > 0) {
                write(sock, file_buffer, bytes_read);
            }
            fclose(fp);
            printf("[DEBUG] File sent: %s\n", filename);
		} else {
			sprintf(name_msg,"%s %s", name, msg);
			write(sock, name_msg, strlen(name_msg));
		}
	}
	return NULL;
}
	
void *recv_msg(void * arg)   // read thread main
{
	int sock = *((int*)arg);
	char name_msg[NAME_SIZE+BUF_SIZE];
	int str_len;
	char filename[BUF_SIZE];
	char *ptr;

	while (1)
	{
		str_len = read(sock, name_msg, NAME_SIZE+BUF_SIZE-1);
		if (str_len == -1) 
			return (void*)-1;

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
            while ((bytes_read = read(sock, file_buffer, sizeof(file_buffer))) > 0) {
                fwrite(file_buffer, 1, bytes_read, fp);
				
				if (bytes_read < BUF_SIZE)
					break;
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
