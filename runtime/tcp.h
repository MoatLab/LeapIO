#ifndef __LEAP_TCP_H
#define __LEAP_TCP_H

#define MAX_TMPBUF (1024)
#define PORTNUMLEN (32)

#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_PORT (1111)


enum {
    SOCK_CLIENT = 0,
    SOCK_SERVER = 1,
    SOCK_AZURE = 2
};

int leap_sock_create(const char *ip, int port, int type);
void leap_sock_close(int sockfd);
int leap_sock_client(const char *ip, int port);
int leap_sock_server(const char *ip, int port);
int leap_sock_accept(int sockfd);

int leap_send(int sockfd, void *buf, int len);
int leap_recv(int sockfd, void *buf, int len);

void show_ifaddrs();

int setup_client(char *serv_ip, bool is_server);
int setup_server(bool is_server);

int leap_nonblock_read(int sfd, void *buf, int len);
int leap_nonblock_write(int sfd, void *buf, int len);
int leap_nonblock_readv(int sfd, struct iovec *iov, int iovcnt);
int leap_nonblock_writev(int sfd, struct iovec *iov, int iovcnt);

#endif
