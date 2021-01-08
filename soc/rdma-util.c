/*
 * File rdma-util.c
 *
 * User-space RDMA utilities for LeapIO
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 *
 */

#include "rdma-util.h"

void leap_register_memory(struct rdma_context *rctx)
{
    struct leap *leap = rctx->leap;

    /* rdmabuf_mr is for both send and recv buf */
    TEST_Z(rctx->rdmabuf_mr = ibv_reg_mr(
                rctx->pd,
                leap->rdmabuf,
                leap->rdmabuflen,
                IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE));

    ///////////////////////////////////////////////////////////////////////////
#if 0
    struct ibv_exp_reg_mr_in in = {0};

    /* Set IBV_ACCESS flags */

    unsigned long my_access_flags = IBV_ACCESS_LOCAL_WRITE |
                      IBV_ACCESS_REMOTE_READ |
                      IBV_ACCESS_REMOTE_WRITE |
                      IBV_ACCESS_REMOTE_ATOMIC |
                      IBV_EXP_ACCESS_PHYSICAL_ADDR;

    /* Allocate a physical MR - allowing access to all memory */
    in.pd = rctx->pd;
    in.addr = NULL; // Address when registering must be NULL
    in.length = 0; // Memory length must be 0
    in.exp_access = my_access_flags;
    struct ibv_mr *physical_mr = ibv_exp_reg_mr(&in);
    if (!physical_mr) {
        printf("PHY MR reg FAILED!!!\n");
    } else {
        printf("PHY MR reg SUCCESS ~~\n");
    }
    exit(1);
#endif
}

void build_context(struct rdma_context *rctx, struct ibv_context *verbs)
{
    printf("Building ibv_context...\n");

    rctx->ibvctx = verbs;

    TEST_Z(rctx->pd = ibv_alloc_pd(rctx->ibvctx));
    TEST_Z(rctx->comp_channel = ibv_create_comp_channel(rctx->ibvctx));
    TEST_Z(rctx->cq = ibv_create_cq(rctx->ibvctx, 4096, NULL, rctx->comp_channel, 0));
    TEST_NZ(ibv_req_notify_cq(rctx->cq, 0));
}

void build_qp_attr(struct rdma_context *rctx, struct ibv_qp_init_attr *qp_attr)
{
    printf("Building qp_init_attr...\n");
    memset(qp_attr, 0, sizeof(*qp_attr));

    qp_attr->send_cq = rctx->cq;
    qp_attr->recv_cq = rctx->cq;
    qp_attr->qp_type = IBV_QPT_RC;

    qp_attr->cap.max_send_wr = 1024;
    qp_attr->cap.max_recv_wr = 1024;
    qp_attr->cap.max_send_sge = 2;
    qp_attr->cap.max_recv_sge = 2;
    qp_attr->cap.max_inline_data = 1; // TODO
}

void die(const char *reason)
{
    fprintf(stderr, "%s\n", reason);
    exit(EXIT_FAILURE);
}

