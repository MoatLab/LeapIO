#ifndef __RDMA_H__
#define __RDMA_H__

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

enum rctx_state {
    IDLE = 1,
    CONNECT_REQUEST,
    ADDR_RESOLVED,
    ROUTE_RESOLVED,
    CONNECTED,
    RDMA_READ_ADV,
    RDMA_READ_COMPLETE,
    RDMA_WRITE_ADV,
    RDMA_WRITE_COMPLETE,
    ERROR
};

struct nvme_qpair;

struct rctx {
    struct rdma_cm_id *cm_id;
    int rid;

    struct list_head list;
    struct ib_cq *cq;
    struct ib_pd *pd;
    struct ib_mr *dma_mr;
    struct ib_qp *qp;

    u16 port;
    u8 addr[16];
    char addr_str[32];

    /* Coperd: for sending CMD */
    void *sbuf;
    u64 sbuf_dma_addr;
    /* Coperd: for recving CPL */
    void *rbuf;
    u64 rbuf_dma_addr;

    /* Coperd: sge and wr 1:1 mapping for now */
    struct ib_sge ssges[1024];
    struct ib_sge rsges[1024];
    struct ib_recv_wr rwrs[1024];
    struct ib_send_wr swrs[1024];

    enum rctx_state state;
    wait_queue_head_t sem;

    struct nvme_qpair *vqp;
};

extern struct rctx rctxs[16];


int wpt_rdma_init(struct rctx *rctx);
int wpt_post_initial_recvs(struct rctx *rctx);
int wpt_setup_wrs(struct rctx *rctx);
void wpt_rdma_deinit(struct rctx *rctx);
void wpt_check_cmpls(struct rctx *rctx);

#endif
