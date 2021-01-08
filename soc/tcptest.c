/*
 * File tcptest.c, a simple tcp client/server testing program
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/tcp.h>
#include "tcp.h"

#define BUF_SIZE 512

static void usage()
{
    printf("\n    Usage:\n"
            "        Server: ./tcptest -s port\n"
            "        Client: ./tcptest -c IP port\n\n");
}

int main(int argc, char **argv)
{
    int fds[2] = {-1, -1};
    char *sip = (char *)DEFAULT_IP;
    int port = DEFAULT_PORT;
    char buf[2][BUF_SIZE] = {'0'};
    int rc = -1;
    int i;

    if (argc < 2) {
        usage();
        exit(1);
    }

    if (strcmp(argv[1], "-c") == 0) {
        if (argc != 4) {
            printf("Coperd,client connects to default server:%s,%d\n", sip, port);
        } else {
            /* Coperd: TODO: validaty check */
            sip = argv[2];
            port = atoi(argv[3]);
        }

        /* Coperd: two sockets sharing the same port */
        for (i = 0; i < 2; i++) {
            memset(buf[i], 0, BUF_SIZE);
            fds[i] = leap_sock_client(sip, port);
            printf("Coperd, connected, %d\n", fds[i]);
        }

        strcpy(buf[0], "msgfromclient");
        rc = write(fds[0], buf[0], 16);
        printf("Coperd, client writes %d bytes to server ... errno:%d\n", rc, errno);

client_retry:
        rc = read(fds[1], buf[1], 16);
        if (rc == -1) {
            if (errno == EAGAIN) {
                goto client_retry;
            }
        }
        printf("Coperd, client read from server: \"%s\", %d bytes\n", buf[1], rc);
    } else if (strcmp(argv[1], "-s") == 0) {
        if (argc == 4) {
            sip = argv[2];
            port = atoi(argv[3]);
        }
        printf("Coperd,server at [%s:%d]\n", sip, port);
        int tfd = leap_sock_server(sip, port);
        int sfd = -1;
        int cnt = 0;
        /* Coperd: busy wait for client connections */
        while (sfd < 0 && cnt != 2) {
            sfd = leap_sock_accept(tfd);
            if (sfd > 0) {
                fds[cnt] = sfd;
                printf("Coperd,accepted one,fd:%d,cnt:%d\n", fds[cnt], cnt);
                cnt++;
                sfd = -1;
            }
        }
        printf("Coperd,server fds[0]:%d,fds[1]:%d\n", fds[0], fds[1]);
        memset(buf[0], 0, BUF_SIZE);
        memset(buf[1], 0, BUF_SIZE);

server_retry:
        rc = read(fds[0], buf[0], 16);
        if (rc == -1) {
            if (errno == EAGAIN) {
                goto server_retry;
            }
        }
        printf("Coperd, read from client: \"%s\", %d bytes\n", buf[0], rc);
        strcpy(buf[1], "msgfromserver");
        rc = write(fds[1], buf[1], 16);
        printf("Coperd, server writes %d bytes to client\n", rc);
    }

    printf("the end\n");

#if 0
    show_ifaddrs();
#endif

    return 0;
}
