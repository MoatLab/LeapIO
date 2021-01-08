#ifndef __RDMA_UTIL_H
#define __RDMA_UTIL_H

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <rdma/rdma_cma.h>

#include "inc/leap.h"
#include "globals.h"

#define RBUF_SIZE 4096

enum {
    LEAP_RDMA_SEND = 0,
    LEAP_RDMA_RECV = 1
};

#define TIMEOUT_IN_MS       (500)

void die(const char *reason);

/*
 * Test method, exit program when return value is/not zero
 */
#define TEST_NZ(x) \
    do { \
        if ( (x)) { \
            abort(); \
            die("error: " #x " failed (returned non-zero)." ); \
        } \
    } while (0)

#define TEST_Z(x) \
    do { \
        if (!(x)) { \
            abort(); \
            die("error: " #x " failed (returned zero/null)."); \
        } \
    } while (0)

/*
 * rdma related variables, such as protection domain, completion channel
 * poller thread, rdma_id etc.
 */
struct rdma_context {
    struct leap *leap;
    int rid;
    struct ibv_context *ibvctx;
    struct ibv_qp *qp;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_comp_channel *comp_channel;

    struct rdma_cm_event *event;
    struct rdma_cm_id *id;
    struct rdma_cm_id *conn_id;
    struct rdma_event_channel *ec;

    struct ibv_mr *host_mr; /* For future zero-copy RDMASSD */
    struct ibv_mr *rdmabuf_mr;
    struct ibv_mr *cmd_mr;
    struct ibv_mr *cpl_mr;

    struct ibv_mr *nvme_qpair_mr;

    pthread_t cq_poller_thread;

    void *host_as_base_va;
};

void *server_cm_event_ts(void *arg);
void *server_cm_event_ts2(void *arg);
void *client_cm_event_ts(void *arg);

void build_context(struct rdma_context *rctx, struct ibv_context *verbs);
void build_qp_attr(struct rdma_context *rctx, struct ibv_qp_init_attr *qp_attr);

void leap_register_memory(struct rdma_context *rctx);
void leap_client_post_recv(struct rdma_context *rctx, nvme_req *rreq);
void leap_client_post_recv2(struct rdma_context *rctx, nvme_req *rreq);
void leap_server_post_recv(struct rdma_context *rctx, nvme_req *req);
void leap_client_post_send(struct rdma_context *rctx, nvme_req *req);
void leap_client_post_send2(struct rdma_context *rctx, nvme_req *req);
void leap_server_post_send(struct rdma_context *rctx, nvme_req *req);

void leap_server_copy_data_to_sbuf(nvme_req *req);
void leap_client_copy_data_from_rbuf(nvme_req *req, void *req_rbuf);
void leap_server_copy_data_from_rbuf(nvme_req *req, void *req_rbuf);
void leap_client_copy_data_to_sbuf(nvme_req *req);

void leap_server_post_initial_recvs(struct leap *leap, struct nvme_qpair *pqp);
void leap_client_post_initial_recvs(struct leap *leap, struct nvme_qpair *vqp);
void leap_client_post_initial_recvs2(struct leap *leap, struct nvme_qpair *vqp);

#endif
