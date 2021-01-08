/*
 * File rdma-leap.c
 *
 * Utilities for NVMe-over-RDMA in LeapIO. LeapIO used a customized "protocol"
 * for transfering NVMe data across RDMA, and is different from the standard
 * NVMe-oF.
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include "rdma-util.h"
#include <time.h>

#define LEAP_ENABLE_MEMCPY

#if defined(DEBUG_VQP) || defined(DEBUG_PQP)
uint64_t get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return (ts.tv_sec * 1e9 + ts.tv_nsec);
}
#endif

void leap_print_nvmecqe(volatile struct nvme_completion *cqe)
{
    printf("sq_head=%d,sq_id=%d,cid=%d,status=%d\n", cqe->sq_head, cqe->sq_id,
            cqe->cid, cqe->status);
}

/*
 * When server receives connection request from client,
 * initialize RDMA attributes, mem, post recv, then accept the connection
 */
int server_on_connect_request(struct leap *leap, struct rdma_cm_id *id)
{
    struct ibv_qp_init_attr qp_attr;
    struct rdma_conn_param cm_params;
    struct rdma_context *rctx = &leap->rctx[leap->nr_connected++];

    rctx->conn_id = id;
    id->context = rctx;

    printf("Receive a connection request on id:%p, rctx[%p],
            id->context=%p,connected=%d\n", id, rctx, id->context,
            leap->nr_connected);

    build_context(rctx, id->verbs);
    build_qp_attr(rctx, &qp_attr);

    TEST_NZ(rdma_create_qp(id, rctx->pd, &qp_attr));
    rctx->qp = id->qp;

    printf("Coperd,QP attr:\n"
            " - max_send_wr[%d], max_recv_wr[%d]\n"
            " - max_send_sge[%d], max_recv_sge[%d]\n"
            " - max_inline_data[%d]\n",
            qp_attr.cap.max_send_wr,
            qp_attr.cap.max_recv_wr,
            qp_attr.cap.max_send_sge,
            qp_attr.cap.max_recv_sge,
            qp_attr.cap.max_inline_data);

    leap_register_memory(rctx);
    printf("Coperd,after leap_register_memory\n");

    memset(&cm_params, 0, sizeof(cm_params));
    TEST_NZ(rdma_accept(id, &cm_params));

    return 0;
}

int server_on_connection(void *rctx)
{
    struct leap *leap = ((struct rdma_context *)rctx)->leap;

    printf("Connection on rctx(%p) established...\n", rctx);

    printf("Coperd,leap->nr_connected=%d\n", leap->nr_connected);
    if (leap->nr_connected == NR_DBVMS) {
        /* all connected, exit cm_event thread */
        return 1;
    }

    /* wait for other connections */
    return 0;
}

/*
 *  On disconnect, free all variables
 */
int server_on_disconnect(struct rdma_cm_id *id)
{
    printf("Peer disconnected...\n");

    rdma_destroy_qp(id);
    rdma_destroy_id(id);

    return 0;
}

int server_on_cm_event(struct leap *leap, struct rdma_cm_event *event)
{
    int r = 0;

    printf("Coperd,%s,event->id=%p,event->id->context=%p\n", __func__,
            event->id, event->id->context);

    if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST) {
        printf("Server establishing a new connection...\n");
        r = server_on_connect_request(leap, event->id);
    } else if (event->event == RDMA_CM_EVENT_ESTABLISHED)
        r = server_on_connection(event->id->context);
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED)
        r = server_on_disconnect(event->id);
    else
        die("Unknown event type on RMDA Event Channel");

    return r;
}

void *server_cm_event_ts(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct rdma_cm_event *event, event_copy;

    /* Coperd: rdma_get_cm_event by default will block until event happens */
    while (rdma_get_cm_event(leap->ec, &event) == 0) {
        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);

        if (server_on_cm_event(leap, &event_copy)) {
            printf("Server cm_event_loop done..\n");
            break;
        }
    }

    /* FIXME */
#if 0
    for (i = 0; i < NR_DBVMS; i++) {
        rctx = &leap->rctx[i];
        rdma_destroy_id(rctx->id);
    }
    rdma_destroy_event_channel(leap->ec);
#endif

    return NULL;
}

/*
 * After client resolve addr of server, initialize all RDMA variables
 * and memory chunks
 */
int client_on_addr_resolved(struct leap *leap, struct rdma_cm_id *id)
{
    struct ibv_qp_init_attr qp_attr;
    struct rdma_context *rctx = &leap->rctx[leap->nr_resolved++];
    id->context = rctx;
    rctx->conn_id = id;

    printf("Client resolved server addr [%d], assign rctx to id->contex: %p\n",
            leap->nr_resolved, rctx);

    build_context(rctx, id->verbs);
    build_qp_attr(rctx, &qp_attr);

    TEST_NZ(rdma_create_qp(id, rctx->pd, &qp_attr));
    rctx->qp = id->qp;
    /* FIXME: no need to register memory every time */
    leap_register_memory(rctx);
    printf("Coperd,after leap_register_memory\n");

    TEST_NZ(rdma_resolve_route(id, TIMEOUT_IN_MS));

    return 0;
}

int client_on_route_resolved(struct rdma_cm_id *id)
{
    struct rdma_conn_param cm_params;
    struct rdma_context *rctx = (struct rdma_context *)id->context;

    printf("Route resolved event id:%p, id->ctx[%d]...\n", id, rctx->rid);
    memset(&cm_params, 0, sizeof(cm_params));
    TEST_NZ(rdma_connect(id, &cm_params));

    return 0;
}

/* Establish connection with server, 0 to continue, 1 to end cm_event thread */
int client_on_connection(struct leap *leap, void *ctx)
{
    struct rdma_context *rctx = (struct rdma_context *)ctx;

    printf("Client on_connection rctx[%p], cm_id:%p connected to server\n",
            rctx, rctx->conn_id);
    leap->nr_connected++;

    if (leap->nr_connected == NR_DBVMS) {
        /* all connected, return 1 to end cm_event thread  */
        return 1;
    }

    /* continue other connections */
    return 0;
}

int client_on_disconnect(struct rdma_cm_id *id)
{
    printf("Peer disconnected...\n");

    rdma_destroy_qp(id);
    rdma_destroy_id(id);

    return 0;
}

int client_on_cm_event(struct leap *leap, struct rdma_cm_event *event)
{
    int r = 0;

    printf("Client on_cm_event (event->id=%p, event->id->context=%p)...\n",
            event->id, event->id->context);

    if (event->event == RDMA_CM_EVENT_ADDR_RESOLVED)
        /* this event carries a new rdma_cm_id */
        r = client_on_addr_resolved(leap, event->id);
    else if (event->event == RDMA_CM_EVENT_ROUTE_RESOLVED)
        r = client_on_route_resolved(event->id);
    else if (event->event == RDMA_CM_EVENT_ESTABLISHED)
        r = client_on_connection(leap, event->id->context);
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED)
        r = client_on_disconnect(event->id);
    else
        die("Unknown event type on RMDA Event Channel");

    return r;
}

void *client_cm_event_ts(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct rdma_cm_event *event, event_copy;

    printf("Client cm_event_loop starts...\n");
    while (rdma_get_cm_event(leap->ec, &event) == 0) {
        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);

        if (client_on_cm_event(leap, &event_copy)) {
            printf("Client cm_event_loop done..\n");
            break;
        }
    }

    /* FIXME: we might still need ec in the middle */
#if 0
    rdma_destroy_event_channel(leap->ec);
#endif

    return NULL;
}

void leap_server_copy_data_to_sbuf(nvme_req *req)
{
#ifdef LEAP_ENABLE_MEMCPY
    uintptr_t sbuf_data = (uintptr_t)req->sbuf + 4096;
#ifdef DEBUG_PQP
    uint64_t st_ns, et_ns;
#endif
    int i;

#ifdef DEBUG_PQP
    st_ns = get_ns();
#endif
    for (i = 0; i < req->iovcnt; i++) {
        memcpy((void *)sbuf_data, req->iov[i].iov_base, req->iov[i].iov_len);
        sbuf_data += req->iov[i].iov_len;
#ifdef DEBUG_PQP
        printf("Coperd,req[%d],iov[%d],len:%ld\n", req->id, i, req->iov[i].iov_len);
#endif
    }
#ifdef DEBUG_PQP
    et_ns = get_ns();
    printf("Coperd,%s,req[%d].iovcnt=%d,t=%.2f us\n", __func__, req->id,
            req->iovcnt, (et_ns - st_ns) * 1.0 / 1e3);
#endif
#endif
}

/* For submitter write: copy req->iov data to (req->sbuf+4096) */
void leap_client_copy_data_to_sbuf(nvme_req *req)
{
#ifdef LEAP_ENABLE_MEMCPY
    /* we reserve the first page winthin sbuf for cmd */
    uintptr_t sbuf_data = (uintptr_t)req->sbuf + 4096;
#ifdef DEBUG_VQP
    uint64_t st_ns, et_ns;
#endif
    int i;

#ifdef DEBUG_VQP
    st_ns = get_ns();
#endif
    for (i = 0; i < req->iovcnt; i++) {
        memcpy((void *)sbuf_data, req->iov[i].iov_base, req->iov[i].iov_len);
        sbuf_data += req->iov[i].iov_len;
#ifdef DEBUG_VQP
        printf("Coperd,req[%d],iov[%d],len:%ld\n", req->id, i, req->iov[i].iov_len);
#endif
    }
#ifdef DEBUG_VQP
    et_ns = get_ns();
    printf("Coperd,%s,req[%d].iovcnt=%d,t=%.2f us\n", __func__, req->id,
            req->iovcnt, (et_ns - st_ns) * 1.0 / 1e3);
#endif
#endif
}

void leap_client_copy_data_from_rbuf(nvme_req *req, void *req_rbuf)
{
#ifdef LEAP_ENABLE_MEMCPY
    uintptr_t rbuf_data = (uintptr_t)req_rbuf + 4096;
#ifdef DEBUG_VQP
    uint64_t st_ns, et_ns;
#endif
    int i;

#ifdef DEBUG_VQP
    st_ns = get_ns();
#endif
    for (i = 0; i < req->iovcnt; i++) {
#ifdef DEBUG_VQP
        printf("Coperd,req[%d],iov[%d]:%p,len:%ld\n", req->id, i,
                req->iov[i].iov_base, req->iov[i].iov_len);
#endif
        memcpy(req->iov[i].iov_base, (void *)rbuf_data, req->iov[i].iov_len);
        rbuf_data += req->iov[i].iov_len;
    }

#ifdef DEBUG_VQP
    et_ns = get_ns();
    printf("Coperd,%s,req[%d].iovcnt=%d,t=%.2f us\n", __func__, req->id,
            req->iovcnt, (et_ns - st_ns) * 1.0 / 1e3);
#endif
#endif
}

void leap_server_copy_data_from_rbuf(nvme_req *req, void *req_rbuf)
{
#ifdef LEAP_ENABLE_MEMCPY
    uintptr_t rbuf_data = (uintptr_t)req_rbuf + 4096;
#ifdef DEBUG_PQP
    uint64_t st_ns, et_ns;
#endif
    int i;

#ifdef DEBUG_PQP
    st_ns = get_ns();
#endif
    for (i = 0; i < req->iovcnt; i++) {
        memcpy(req->iov[i].iov_base, (void *)rbuf_data, req->iov[i].iov_len);
        rbuf_data += req->iov[i].iov_len;
#ifdef DEBUG_PQP
        printf("Coperd,req[%d],iov[%d],len:%ld\n", req->id, i, req->iov[i].iov_len);
#endif
    }
#ifdef DEBUG_PQP
    et_ns = get_ns();
    printf("Coperd,%s,req[%d].iovcnt=%d,t=%.2f us\n", __func__, req->id,
            req->iovcnt, (et_ns - st_ns) * 1.0 / 1e3);
#endif
#endif
}

void leap_client_post_send(struct rdma_context *rctx, nvme_req *req)
{
    struct ibv_send_wr swr, *bad_wr = NULL;
    struct ibv_sge sge[2];
    int opc = req->cmd.rw.opcode;
    int nr_sges;

    /* store NVMe command at the beginning of req->rbuf */
    memcpy(req->sbuf, &req->cmd, NVME_CMD_SZ);

    memset(&swr, 0, sizeof(swr));
    sge[0].addr = (uintptr_t)req->sbuf;
    sge[0].length = NVME_CMD_SZ;
    sge[0].lkey = rctx->rdmabuf_mr->lkey;
    nr_sges = 1;

    /* store data (if any) afterwards */
    if (opc == NVME_CMD_WRITE || opc == NVM_OP_PWRITE) {
        leap_client_copy_data_to_sbuf(req);
        sge[1].addr = (uintptr_t)req->sbuf + 4096;
        sge[1].length = req->len; /* by now, req->len already updated */
        sge[1].lkey = rctx->rdmabuf_mr->lkey;
        nr_sges++;
    }

    /* TODO: design a spec for wr_id (64bits) later */
    swr.wr_id = req->id;
    swr.opcode = IBV_WR_SEND;
    swr.sg_list = sge;
    swr.num_sge = nr_sges;
    /* TODO: need this at all? maybe only for testing */
    swr.send_flags = IBV_SEND_SIGNALED;

    TEST_NZ(ibv_post_send(rctx->qp, &swr, &bad_wr));
#ifdef DEBUG_VQP
    printf("Coperd,%s,sent out req[%d] over RDMA QP[%d]\n", __func__, req->id,
            rctx->rid);
#endif
}

void leap_server_post_send(struct rdma_context *rctx, nvme_req *req)
{
    struct ibv_send_wr swr, *bad_wr = NULL;
    struct ibv_sge sge[2];
    int opc = req->cmd.rw.opcode;
    int nr_sges = 0;

    /* store NVMe command in the first page */
    memcpy(req->sbuf, &req->cpl, NVME_CPL_SZ);
#ifdef DEBUG_PQP
    printf("Coperd,%s,req[%d], ", __func__, req->id);
    leap_print_nvmecqe((struct nvme_completion *)req->rbuf);
#endif

    memset(&swr, 0, sizeof(swr));
    sge[0].addr = (uintptr_t)req->sbuf;
    sge[0].length = NVME_CPL_SZ;
    sge[0].lkey = rctx->rdmabuf_mr->lkey;
    nr_sges = 1;

    if (opc == NVME_CMD_READ || opc == NVM_OP_PREAD) {
        sge[1].addr = (uintptr_t)req->sbuf + 4096;
        sge[1].length = req->len;
        sge[1].lkey = rctx->rdmabuf_mr->lkey;
        nr_sges++;
    }

    swr.wr_id = req->id;
    swr.opcode = IBV_WR_SEND;
    swr.sg_list = sge;
    swr.num_sge = nr_sges;
    swr.send_flags = IBV_SEND_SIGNALED;

    TEST_NZ(ibv_post_send(rctx->qp, &swr, &bad_wr));
}

/* TODO: all the send/recv WRs should be initialized at beginning of SOCP */
void leap_client_post_recv(struct rdma_context *rctx, nvme_req *rreq)
{
    struct ibv_recv_wr rwr, *bad_wr = NULL;
    struct ibv_sge sge[2];

    memset(&rwr, 0, sizeof(rwr));

    /* TODO: Take this out of data path in future */
    sge[0].addr = (uintptr_t)rreq->rbuf;
    sge[0].length = NVME_CPL_SZ;
    sge[0].lkey = rctx->rdmabuf_mr->lkey;

    sge[1].addr = (uintptr_t)rreq->rbuf + 4096;
    sge[1].length = rreq->rbuflen - 4096;
    sge[1].lkey = rctx->rdmabuf_mr->lkey;

    // TODO: design a spec for wr_id (64bits) later
    rwr.wr_id = rreq->id;
    rwr.sg_list = sge;
    rwr.num_sge = 2;
    rwr.next = NULL;

    TEST_NZ(ibv_post_recv(rctx->qp, &rwr, &bad_wr));
}

void leap_server_post_recv(struct rdma_context *rctx, nvme_req *rreq)
{
    struct ibv_recv_wr rwr, *bad_wr = NULL;
    struct ibv_sge sge[2];
    int r;

    memset(&rwr, 0, sizeof(rwr));

    sge[0].addr = (uintptr_t)rreq->rbuf;
    sge[0].length = NVME_CMD_SZ;
    sge[0].lkey = rctx->rdmabuf_mr->lkey;

    sge[1].addr = (uintptr_t)rreq->rbuf + 4096;
    sge[1].length = rreq->rbuflen - 4096;
    sge[1].lkey = rctx->rdmabuf_mr->lkey;

    /* TODO: design a spec for wr_id (64bits) later */
    rwr.wr_id = rreq->id;
    rwr.sg_list = sge;
    rwr.num_sge = 2;
    rwr.next = NULL;

    r = ibv_post_recv(rctx->qp, &rwr, &bad_wr);
    if (r != 0) {
        printf("Coperd,%s,ibv_post_recv failed with ret:%d, errno:%d,%s\n",
                __func__, r, errno, strerror(errno));
        abort();
    }
}

void leap_server_post_initial_recvs(struct leap *leap, struct nvme_qpair *pqp)
{
    struct rdma_context *rctx = &leap->rctx[pqp->qid-1];
    nvme_req *rreq;
    int i;

    for (i = 0; i < 1024; i++) {
        rreq = &pqp->reqs[i];
        assert(rreq);
        leap_server_post_recv(rctx, rreq);
    }
}

void leap_client_post_initial_recvs(struct leap *leap, struct nvme_qpair *vqp)
{
    struct rdma_context *rctx = &leap->rctx[vqp->qid-1];
    nvme_req *rreq;
    int i;

    for (i = 0; i < 1024; i++) {
        rreq = &vqp->reqs[i];
        assert(rreq);
        leap_client_post_recv(rctx, rreq);
    }
}
