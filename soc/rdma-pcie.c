/*
 * File rdma-pcie.c
 * RDMA-based memory sharing between x86 and SoC
 */


#include "rdma-util.h"
#include <time.h>

#define LEAP_ENABLE_MEMCPY

/* Coperd: FIXME: add corresponding variables */
void leap_register_nvme_qpair_buf(struct rdma_context *rctx)
{
    struct leap *leap = rctx->leap;

    if (!leap->nvme_qpair_buf) {
        printf("QP-PCIe: Allocating qpair_buf ..\n");
        leap->nvme_qpair_buf_len = RBUF_SIZE * 1024 * NR_DBVMS;
        posix_memalign(&leap->nvme_qpair_buf, 4096, leap->nvme_qpair_buf_len);
        assert(leap->nvme_qpair_buf && ((uintptr_t)leap->nvme_qpair_buf % 4096 == 0));
    }

    /* rdmabuf_mr is for both send and recv buf */
    /* Only register for 80KB for each rctx */
    TEST_Z(rctx->nvme_qpair_mr = ibv_reg_mr(
                rctx->pd,
                leap->nvme_qpair_buf + RBUF_SIZE * 1024 * rctx->rid,
                RBUF_SIZE * 1024,
                IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE));
    printf("QP-PCIe: Registered nvme_qpair_buf MR for rctx[%d]\n", rctx->rid);
}

/*
 * When server receives connection request from client,
 * initialize RDMA attributes, mem, post recv, then accept the connection
 */
int server_on_connect_request2(struct leap *leap, struct rdma_cm_id *id)
{
    struct ibv_qp_init_attr qp_attr;
    struct rdma_conn_param cm_params;
    struct rdma_context *rctx = &leap->rctx2[leap->nr_connected2++];

    rctx->conn_id = id;
    id->context = rctx;

    printf("QP-PCIe: Receive a connection request on id:%p, rctx[%p],"
            "id->context=%p,connected=%d\n", id, rctx, id->context,
            leap->nr_connected2);

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

    leap_register_nvme_qpair_buf(rctx);
    printf("QP-PCIe,after leap_register_memory\n");

    memset(&cm_params, 0, sizeof(cm_params));
    TEST_NZ(rdma_accept(id, &cm_params));

    return 0;
}

int server_on_connection2(void *rctx)
{
    struct leap *leap = ((struct rdma_context *)rctx)->leap;

    printf("Connection on rctx(%p) established...\n", rctx);

    printf("Coperd,QP-PCIe,leap->nr_connected=%d\n", leap->nr_connected2);
    if (leap->nr_connected2 == NR_DBVMS) {
        /* all connected, exit cm_event thread */
        return 1;
    }

    /* wait for other connections */
    return 0;
}

/*
 *  On disconnect, free all variables
 */
int server_on_disconnect2(struct rdma_cm_id *id)
{
    printf("QP-PCIe, Peer disconnected...\n");

    rdma_destroy_qp(id);
    rdma_destroy_id(id);

    return 0;
}

int server_on_cm_event2(struct leap *leap, struct rdma_cm_event *event)
{
    int r = 0;

    printf("Coperd,QP-PCIe,%s,event->id=%p,event->id->context=%p\n", __func__,
            event->id, event->id->context);

    if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST) {
        printf("QP-PCIe Server establishing a new connection...\n");
        r = server_on_connect_request2(leap, event->id);
    } else if (event->event == RDMA_CM_EVENT_ESTABLISHED)
        r = server_on_connection2(event->id->context);
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED)
        r = server_on_disconnect2(event->id);
    else
        die("QP-PCIe Server: Unknown event type on RMDA Event Channel");

    return r;
}

void *server_cm_event_ts2(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct rdma_cm_event *event, event_copy;

    /* Coperd: rdma_get_cm_event by default will block until event happens */
    while (rdma_get_cm_event(leap->ec2, &event) == 0) {
        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);

        if (server_on_cm_event2(leap, &event_copy)) {
            printf("Server cm_event_loop done..\n");
            break;
        }
    }

    /* FIXME */
#if 0
    for (i = 0; i < NR_DBVMS; i++) {
        rctx = &leap->rctx2[i];
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
int client_on_addr_resolved2(struct leap *leap, struct rdma_cm_id *id)
{
    struct ibv_qp_init_attr qp_attr;
    struct rdma_context *rctx = &leap->rctx2[leap->nr_resolved++];
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

int client_on_route_resolved2(struct rdma_cm_id *id)
{
    struct rdma_conn_param cm_params;
    struct rdma_context *rctx = (struct rdma_context *)id->context;

    printf("Route resolved event id:%p, id->ctx[%d]...\n", id, rctx->rid);
    memset(&cm_params, 0, sizeof(cm_params));
    TEST_NZ(rdma_connect(id, &cm_params));

    return 0;
}

/* Establish connection with server, 0 to continue, 1 to end cm_event thread */
int client_on_connection2(struct leap *leap, void *ctx)
{
    struct rdma_context *rctx = (struct rdma_context *)ctx;
    printf("Client on_connection rctx[%p], cm_id:%p connected to server\n", rctx, rctx->conn_id);
    leap->nr_connected++;

    if (leap->nr_connected == NR_DBVMS) {
        /* all connected, return 1 to end cm_event thread  */
        return 1;
    }

    /* continue other connections */
    return 0;
}

int client_on_disconnect2(struct rdma_cm_id *id)
{
    printf("Peer disconnected...\n");

    rdma_destroy_qp(id);
    rdma_destroy_id(id);

    return 0;
}

int client_on_cm_event2(struct leap *leap, struct rdma_cm_event *event)
{
    int r = 0;

    printf("Client on_cm_event (event->id=%p, event->id->context=%p)...\n",
            event->id, event->id->context);

    if (event->event == RDMA_CM_EVENT_ADDR_RESOLVED)
        /* this event carries a new rdma_cm_id */
        r = client_on_addr_resolved2(leap, event->id);
    else if (event->event == RDMA_CM_EVENT_ROUTE_RESOLVED)
        r = client_on_route_resolved2(event->id);
    else if (event->event == RDMA_CM_EVENT_ESTABLISHED)
        r = client_on_connection2(leap, event->id->context);
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED)
        r = client_on_disconnect2(event->id);
    else
        die("Unknown event type on RMDA Event Channel");

    return r;
}

void *client_cm_event_ts2(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct rdma_cm_event *event, event_copy;

    printf("Client cm_event_loop starts...\n");
    while (rdma_get_cm_event(leap->ec, &event) == 0) {
        memcpy(&event_copy, event, sizeof(*event));
        rdma_ack_cm_event(event);

        if (client_on_cm_event2(leap, &event_copy)) {
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

void leap_client_post_send2(struct rdma_context *rctx, nvme_req *req)
{
    struct ibv_send_wr swr, *bad_wr = NULL;
    struct ibv_sge sge;
    int nr_sges;

    memset(&swr, 0, sizeof(swr));
    sge.addr = (uintptr_t)req->cplbuf;
    sge.length = RBUF_SIZE; //NVME_CPL_SZ;
    sge.lkey = rctx->nvme_qpair_mr->lkey;
    nr_sges = 1;

    /* TODO: design a spec for wr_id (64bits) later */
    swr.wr_id = req->id;
    swr.opcode = IBV_WR_SEND;
    swr.sg_list = &sge;
    swr.num_sge = nr_sges;
    /* TODO: need this at all? maybe only for testing */
    swr.send_flags = IBV_SEND_SIGNALED;

    TEST_NZ(ibv_post_send(rctx->qp, &swr, &bad_wr));
#ifdef DEBUG_VQP
    printf("Coperd,%s,sent out req[%d] over RDMA QP[%d]\n", __func__, req->id, rctx->rid);
#endif
}

void leap_server_post_send2(struct rdma_context *rctx, nvme_req *req)
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

/* For vQP routing */
/* TODO: all the send/recv WRs should be initialized at beginning of SOCP */
void leap_client_post_recv2(struct rdma_context *rctx, nvme_req *rreq)
{
    struct ibv_recv_wr rwr, *bad_wr = NULL;
    struct ibv_sge sge;

    memset(&rwr, 0, sizeof(rwr));

    /* TODO: Take this out of data path in future */
    sge.addr = (uintptr_t)rreq->cmdbuf;
    sge.length = NVME_CMD_SZ;
    sge.lkey = rctx->nvme_qpair_mr->lkey;

    /* TODO: design a spec for wr_id (64bits) later */
    rwr.wr_id = rreq->id;
    rwr.sg_list = &sge;
    rwr.num_sge = 1;
    rwr.next = NULL;

    TEST_NZ(ibv_post_recv(rctx->qp, &rwr, &bad_wr));
}

void leap_server_post_recv2(struct rdma_context *rctx, nvme_req *rreq)
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

void leap_server_post_initial_recvs2(struct leap *leap, struct nvme_qpair *pqp)
{
    struct rdma_context *rctx = &leap->rctx2[pqp->qid-1];
    nvme_req *rreq;
    int i;

    for (i = 0; i < 1024; i++) {
        rreq = &pqp->reqs[i];
        assert(rreq);
        leap_server_post_recv(rctx, rreq);
    }
}

/* For vQP routing */
void leap_client_post_initial_recvs2(struct leap *leap, struct nvme_qpair *vqp)
{
    struct rdma_context *rctx = &leap->rctx2[vqp->qid-1];
    nvme_req *rreq;
    int i;

    for (i = 0; i < 1024; i++) {
        rreq = &vqp->reqs[i];
        assert(rreq);
        leap_client_post_recv2(rctx, rreq);
    }
}
