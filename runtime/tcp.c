/*
 * File tcp.c
 *
 * TCP utilities for LeapIO, used for NVMe-over-TCP
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <netdb.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <linux/tcp.h>

#include "tcp.h"

#define SENDSZ (64) /* Coperd: NVMe command size */
#define RECVSZ (16) /* Coperd: NVMe completion size */

#define DEFAULT_IP   "127.0.0.1"
#define DEFAULT_PORT (1111)

int leap_sock_create(const char *ip, int port, int type)
{
    char portnum[PORTNUMLEN];
    struct addrinfo hints, *rp, *res0;
    int sfd, flag;
    int reuse_addr = 1, reuse_port = 1, val = 1;
    int rc;

    if (ip == NULL) {
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;          /* Only allow IPv4 for now */
    hints.ai_socktype = SOCK_STREAM;    /* TCP socket */
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_flags |= AI_PASSIVE;       /* For wildcard IP addr */
    hints.ai_flags |= AI_NUMERICHOST;
    hints.ai_protocol = 0;              /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    snprintf(portnum, sizeof(portnum), "%d", port);
    rc = getaddrinfo(ip, portnum, NULL, &res0);
    if (rc != 0) {
        printf("getaddrinfo() failed (errno=%d):%s\n", errno, gai_strerror(rc));
        return -1;
    }

    /* try listen */
    sfd = -1;
    for (rp = res0; rp != NULL; rp = rp->ai_next) {
retry:
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd < 0) {
            /* error */
            continue;
        }

        rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(int));
        if (rc != 0) {
            close(sfd);
            /* error */
            continue;
        }
#ifdef SO_REUSEPORT
        rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(int));
        if (rc != 0) {
            close(sfd);
            /* error */
            continue;
        }
#else
        printf("Coperd,%s,cannot reuse port for multi connections!\n", __func__);
        exit(EXIT_FAILURE);
#endif
        rc = setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(int));
        if (rc != 0) {
            close(sfd);
            /* error */
            continue;
        }

        if (type == SOCK_SERVER) {
            rc = bind(sfd, rp->ai_addr, rp->ai_addrlen);
            if (rc != 0) {
                printf("bind() failed at port %d, errno = %d\n", port, errno);
                switch (errno) {
                case EINTR:
                    /* interrupted? */
                    close(sfd);
                    goto retry;
                case EADDRNOTAVAIL:
                    printf("IP address %s not available.\n", ip);
                    /* FALLTHROUGH */
                default:
                    /* try next family */
                    close(sfd);
                    sfd = -1;
                    continue;
                }
            }
            /* bind OK */
            rc = listen(sfd, 512);
            if (rc != 0) {
                printf("listen() failed, errno = %d\n", errno);
                close(sfd);
                sfd = -1;
                break;
            }
        } else if (type == SOCK_CLIENT) {
            rc = connect(sfd, rp->ai_addr, rp->ai_addrlen);
            if (rc != 0) {
                printf("connect() failed, errno = %d\n", errno);
                /* try next family */
                close(sfd);
                sfd = -1;
                continue;
            }
        }

        flag = fcntl(sfd, F_GETFL);
        if (fcntl(sfd, F_SETFL, flag | O_NONBLOCK) < 0) {
            printf("fcntl can't set nonblocking mode for socket, fd: %d (%d)\n",
                    sfd, errno);
            close(sfd);
            sfd = -1;
            break;
        }
        /* Coperd: one succesful listen or connect */
        break;
    }
    freeaddrinfo(res0);

    if (sfd < 0 || rp == NULL) {
        return -1;
    }

    return sfd;
}

int leap_sock_client(const char *ip, int port)
{
    return leap_sock_create(ip, port, SOCK_CLIENT);
}

int leap_sock_server(const char *ip, int port)
{
    return leap_sock_create(ip, port, SOCK_SERVER);
}

int leap_sock_accept(int sockfd)
{
    struct sockaddr_storage sa;
    socklen_t salen;
    int rc;
    int flag;

    memset(&sa, 0, sizeof(sa));
    salen = sizeof(sa);

    rc = accept(sockfd, (struct sockaddr *)&sa, &salen);
    if (rc == -1) {
        return -1;
    }

    flag = fcntl(rc, F_GETFL);
    if ((!(flag & O_NONBLOCK)) && (fcntl(rc, F_SETFL, flag | O_NONBLOCK) < 0)) {
        printf("fcntl can't set nonblocking mode for socket, fd: %d (%d)\n",
                rc, errno);
        close(rc);
        return -1;
    }

    return rc;
}

void leap_sock_close(int sockfd)
{
    close(sockfd);
}

/* Coperd: particularly we're interested in IP and port, TODO */
void show_ifaddrs()
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        /* Display interface name and family (including symbolic
           form of the latter for the common families) */
        printf("%-8s %s (%d)\n",
                ifa->ifa_name,
                (family == AF_PACKET) ? "AF_PACKET" :
                (family == AF_INET) ? "AF_INET" :
                (family == AF_INET6) ? "AF_INET6" : "???",
                family);

        /* For an AF_INET* interface address, display the address */
        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                    sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
        } else if (family == AF_PACKET && ifa->ifa_data != NULL) {
            struct rtnl_link_stats *stats = (struct rtnl_link_stats *)ifa->ifa_data;
            printf("\t\ttx_packets = %10u; rx_packets = %10u\n"
                    "\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
                    stats->tx_packets, stats->rx_packets,
                    stats->tx_bytes, stats->rx_bytes);
        }
    }

    freeifaddrs(ifaddr);
}

int setup_server(bool is_server)
{
    int sockfd, connfd;
    struct sockaddr_in serv_addr, cli;
    //int opt = 1;
    int addrlen = sizeof(cli);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Coperd,socket creation failed\n");
        exit(1);
    }
    printf("Coperd,%s,socket creation SUCCESS,sockfd=%d\n", __func__, sockfd);

#if 0
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                &opt, sizeof(opt))) {
        perror("Coperd,setsockopt failed\n");
        exit(1);
    }
#endif

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(DEFAULT_PORT);
    printf("Coperd,%s,server will listen SUCCESS\n", __func__);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("Coperd,bind failed\n");
        exit(1);
    }
    printf("Coperd,%s,bind SUCCESS\n", __func__);

    if (listen(sockfd, 5) == -1) {
        perror("Coperd,listen failed\n");
        exit(1);
    }

    if ((connfd = accept(sockfd, (struct sockaddr *)&cli,
                    (socklen_t *)&addrlen)) < 0) {
        perror("Coperd,accept failed\n");
        exit(1);
    }

    printf("Coperd,server accepted client\n");
    return connfd;
}

int setup_client(char *serv_ip, bool is_server)
{
    int sockfd = 0;
    //struct sockaddr_in address;
    struct sockaddr_in serv_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("Coperd,socket creation failed\n");
        exit(1);
    }
    printf("Coperd,socket creation SUCCESS\n");

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(serv_ip);
    serv_addr.sin_port = htons(DEFAULT_PORT);
#if 0
    if (inet_pton(AF_INET, serv_ip, &serv_addr.sin_addr.s_addr) <= 0) {
        printf("Coperd,invalid addr\n");
        exit(1);
    }
#endif

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Coperd,connect failed\n");
        exit(1);
    }
    printf("Coperd,client connected to server!\n");

    return sockfd;
}


#if 0
static int leap_setup_server(tcp_server *sp)
{
    sp->listen();
    sp->accept(16, 64);
    printf("Coperd,%s,accepted a connection!\n", __func__);
    return 0;
}

static int leap_setup_client(tcp_client *cp, const char *ip_addr, short serv_port)
{
    cp->connect(ip_addr, serv_port, 64, 16);
    printf("Coperd,%s,connected to a server!\n", __func__);
    return 0;
}
#endif

#define PORT1 (5555)
#define PORT2 (6666)

/* Coperd: do send until len bytes out (assuming nonblock) */
int leap_send(int sockfd, void *buf, int len)
{
    int rem = len;
    int nbytes = 0;

    while (rem > 0) {
        nbytes = send(sockfd, buf, rem, 0);
        if (nbytes == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                /* Coperd: polling on the socket to send data */
                continue;
            }
        } else if (nbytes == 0) {
            /* TODO */
            printf("Coperd,connection lost\n");
            exit(EXIT_FAILURE);
        }
        buf += nbytes;
        rem -= nbytes;
    }

    return 0;
}

/* Coperd: do recv until len bytes in (assuming nonblock) */
int leap_recv(int sockfd, void *buf, int len)
{
    int rem = len;
    int nbytes = 0;

    while (rem > 0) {
        nbytes = recv(sockfd, buf, rem, MSG_WAITALL);
        if (nbytes == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                /* Coperd: polling on the socket to recv data */
                continue;
            }
        } else if (nbytes == 0) {
            /* TODO */
            exit(1);
        }
        buf += nbytes;
        rem -= nbytes;
    }

    return 0;
}

/*
 * @ret
 * > 0: successfully write @ret bytes
 * = 0: EWOULDBLOCK || EAGAIN
 * < 0: write failed
 */
int leap_nonblock_write(int sfd, void *buf, int len)
{
    int rc;

    rc = write(sfd, buf, len);
    if (rc < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            /* Coperd: try luck next time, stop all cmd transfers */
            return 0;
        } else {
            return -1;
        }
    } else if (rc == 0) {
        return -2;
    } else {
        return rc;
    }
}

/*
 * @ret
 * > 0: successfully write @ret bytes
 * = 0: EWOULDBLOCK || EAGAIN
 * < 0: read failed
 */
int leap_nonblock_read(int sfd, void *buf, int len)
{
    int rc;

    rc = read(sfd, buf, len);
    if (rc < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            /* Coperd: try luck next time, stop all cmd transfers */
            return 0;
        } else {
            printf("Coperd,%s,errno=%d,fd=%d\n", __func__, errno, sfd);
            return -1;
        }
    } else if (rc == 0) {
        return -2;
    } else {
        return rc;
    }
}

/*
 * @ret
 * > 0: successfully read @ret bytes
 * = 0: EWOULDBLOCK || EAGAIN
 * < 0: readv failed
 */
int leap_nonblock_readv(int sfd, struct iovec *iov, int iovcnt)
{
    int rc;

    rc = readv(sfd, iov, iovcnt);
    if (rc < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            /* Coperd: try luck next time, stop all cmd transfers */
            return 0;
        } else {
            return -1;
        }
    } else if (rc == 0) {
        return -2;
    } else {
        return rc;
    }
}

/*
 * @ret
 * > 0: successfully write @ret bytes
 * = 0: EWOULDBLOCK || EAGAIN
 * < 0: writev failed
 */
int leap_nonblock_writev(int sfd, struct iovec *iov, int iovcnt)
{
    int rc;

    rc = writev(sfd, iov, iovcnt);
    if (rc < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            /* Coperd: try luck next time, stop all cmd transfers */
            return 0;
        } else {
            return -1;
        }
    } else if (rc == 0) {
        return -2;
    } else {
        return rc;
    }
}
