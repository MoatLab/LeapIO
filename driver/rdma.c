/*
 * File rdma.c
 *
 * Kernel-space RDMA utilities used by LeapIO for cross-PCIe QP sharing
 *
 * Written by Huaicheng <huaicheng@cs.uchicago.edu>
 * Acknowledgements to krping for the control path setup
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/smp.h>
#include <linux/list.h>
#include <linux/lightnvm.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>

#include <asm/atomic.h>
#include <asm/pci.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include "rdma.h"
#include "wpt.h"

//#define RDMA_DEBUG

//#define USE_INT
#define NVME_CPL_DATA_SZ 4096 //NVME_CPL_SZ + 512
#define NVME_CPL_DATA_CNT 1024

static int cm_event_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *e)
{
    int r;
    struct rctx *rctx = cm_id->context;

    switch (e->event) {
    case RDMA_CM_EVENT_ADDR_RESOLVED:
        printk("Coperd,server addr resolved\n");
        rctx->state = ADDR_RESOLVED;
        r = rdma_resolve_route(cm_id, 2000);
        if (r) {
            pr_err("rdma_resolve_route error:%d\n", r);
            wake_up_interruptible(&rctx->sem);
        }
        break;

    case RDMA_CM_EVENT_ROUTE_RESOLVED:
        rctx->state = ROUTE_RESOLVED;
        printk("Coperd,route resolved\n");
        wake_up_interruptible(&rctx->sem);
        break;

    case RDMA_CM_EVENT_CONNECT_REQUEST:
        rctx->state = CONNECT_REQUEST;
        //rctx->child_cm_id = cm_id;
        printk("Coperd,connect request\n");
        wake_up_interruptible(&rctx->sem);
        break;

    case RDMA_CM_EVENT_ESTABLISHED:
        printk("Coperd,%s,connected!\n", __func__);
        rctx->state = CONNECTED;
        wake_up_interruptible(&rctx->sem);
        break;

    case RDMA_CM_EVENT_ADDR_ERROR:
    case RDMA_CM_EVENT_ROUTE_ERROR:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    case RDMA_CM_EVENT_UNREACHABLE:
    case RDMA_CM_EVENT_REJECTED:
        pr_err("Coperd,event:%d,error:%d", e->event, e->status);
        rctx->state = ERROR;
        break;
    default:
        printk("Coperd, unsupported event type:%d\n", e->event);
    }

    return 0;
}

/* Coperd: only support IPv4 for now */
static void fill_sockaddr(struct sockaddr_storage *sin, struct rctx *rctx)
{
    struct sockaddr_in *sin4;

    memset(sin, 0, sizeof(struct sockaddr_storage));
    sin4 = (struct sockaddr_in *)sin;
    sin4->sin_family = AF_INET;
    memcpy((void *)&sin4->sin_addr.s_addr, rctx->addr, 4);
    sin4->sin_port = rctx->port;
}

static bool reg_supported(struct ib_device *dev)
{
    u64 flags = IB_DEVICE_MEM_MGT_EXTENSIONS;

    printk("Coperd,dev=%p\n", dev);

    if ((dev->attrs.device_cap_flags & flags) != flags) {
        pr_err("Fastreg not supported\n");
        return false;
    }

    return true;
}

static int create_qp(struct rctx *rctx)
{
    struct ib_qp_init_attr init_attr;
    int r;

    memset(&init_attr, 0, sizeof(struct ib_qp_init_attr));

    init_attr.cap.max_send_wr = NVME_CPL_DATA_CNT;
    init_attr.cap.max_recv_wr = NVME_CPL_DATA_CNT;
    init_attr.cap.max_recv_sge = 2;
    init_attr.cap.max_send_sge = 2;

    init_attr.qp_type = IB_QPT_RC;
    init_attr.send_cq = rctx->cq;
    init_attr.recv_cq = rctx->cq;
    init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

    r = rdma_create_qp(rctx->cm_id, rctx->pd, &init_attr);
    if (!r) {
        rctx->qp = rctx->cm_id->qp;
    }

    return r;
}

static void process_nvme_cqe(struct nvme_qpair *vqp, struct nvme_completion *cqe)
{
    if (nvme_cq_full(vqp)) {
        pr_err("Error: vCQ[%d] full", vqp->qid);
        return;
    }

    //printk("Coperd,CQE,sqid:%d,cid:%d\n", cqe->sq_id, cqe->cid);
    memcpy((void *)&vqp->cqes[vqp->cq_tail], cqe, NVME_CPL_SZ);
    nvme_inc_cq_tail(vqp);
}

/* Coperd: we don't care if it overflows */
static u32 si_cnt = 1;

static void cq_event_handler(struct ib_cq *cq, void *ctx)
{
    struct rctx *rctx = (struct rctx *)ctx;
    int r;
    struct ib_wc wc;
    struct ib_recv_wr *bad_wr;
    struct ib_recv_wr *owr;
    struct nvme_completion *cqe;
    int id;

    BUG_ON(rctx->cq != cq);

#ifdef USE_INT
    ib_req_notify_cq(rctx->cq, IB_CQ_NEXT_COMP);
#endif

    while ((r = ib_poll_cq(rctx->cq, 1, &wc)) == 1) {
        //printk("Coperd,%s,recv sth ...\n", __func__);
        if (wc.status) {
            pr_err("Coperd,cq completion failed with id: %Lx status %d opc %d"
                    "vendor_err %x\n", wc.wr_id, wc.status, wc.opcode, wc.vendor_err);
            return;
        }

        switch (wc.opcode) {
        case IB_WC_RECV:
#ifdef RDMA_DEBUG
            printk("Coperd,recv %d bytes\n", wc.byte_len);
#endif
            id = (int)wc.wr_id;
            cqe = (struct nvme_completion *)((uintptr_t)rctx->rbuf + id * NVME_CPL_DATA_SZ);
            process_nvme_cqe(rctx->vqp, cqe);

            BUG_ON(rctx->sbuf == NULL);
            struct nvme_command *cmd = &((struct nvme_command *)rctx->sbuf)[cqe->cid];
            BUG_ON(cmd == NULL);

            //pr_info("this prp1 [RECV] %llu, CID %d\n", cmd->rw.dptr.prp.prp1, cqe->cid);

            struct page *page = pfn_to_page(le64_to_cpu(cmd->rw.dptr.prp.prp1) >> PAGE_SHIFT);
            if(page != NULL) {
                void *vaddr = vmap(&page, 1, VM_MAP, PAGE_KERNEL_NOCACHE);
                if(vaddr != NULL) {
                    //memcpy(vaddr, (void *)cqe, NVME_CPL_DATA_SZ);
                } else {
                    // should never print
                    pr_info("vaddr is NULL\n");
                }
            }

            /*
             * Increse vqp->si_db doorbell to let ats thread do interrupt
             */
            /* TODO: is this safe?? Need to be atomic?? */
            *(rctx->vqp->si_db) = si_cnt;
            si_cnt++;

            /* Coperd: once cpl processing is done, post another recv */
            /* Can we directly do this by reusing the old WR? */
            owr = &rctx->rwrs[id];
            r = ib_post_recv(rctx->qp, owr, &bad_wr);
            if (r) {
                pr_err("Coperd,post recv errno:%d\n", r);
                return;
            }
            break;

        case IB_WC_SEND:
            //printk("Coperd,send one cmd(%d bytes) out\n", wc.byte_len);
            break;

        default:
            pr_err("Coperd,unexpected opcode:%d\n", wc.opcode);
            return;
        }
    }
}

static int setup_qp(struct rctx *rctx, struct rdma_cm_id *cm_id)
{
    int r;
    struct ib_cq_init_attr attr = {0};

    rctx->pd = ib_alloc_pd(cm_id->device, 0/*IB_PD_UNSAFE_GLOBAL_RKEY*/);
    if (IS_ERR(rctx->pd)) {
        pr_err("ib_alloc_pd failed:\n");
        return PTR_ERR(rctx->pd);
    }

    attr.cqe = 2048;
    attr.comp_vector = 0;
    rctx->cq = ib_create_cq(cm_id->device, cq_event_handler, NULL, rctx, &attr);
    if (IS_ERR(rctx->cq)) {
        pr_err("Coperd,%s,ib_create_cq failed\n", __func__);
        r = PTR_ERR(rctx->cq);
        goto err_create_cq;
    }

#ifdef USE_INT
    r = ib_req_notify_cq(rctx->cq, IB_CQ_NEXT_COMP);
    if (r) {
        pr_err("Coperd,%s,ib_req_notify_cq failed\n", __func__);
    }
#endif

    r = create_qp(rctx);
    if (r) {
        pr_err("Coperd,rdma_create_qp failed:%d\n", r);
        goto err_create_qp;
    }

    return 0;

err_create_qp:
    ib_destroy_cq(rctx->cq);
err_create_cq:
    ib_dealloc_pd(rctx->pd);

    return r;
}

int wpt_rdma_init(struct rctx *rctx)
{
    int r;
    struct sockaddr_storage sin;
    struct rdma_conn_param conn_param;

    if (rctx->state >= CONNECTED) {
        printk("Coperd,rctx[%d] is already in CONNECTED state..\n", rctx->rid);
        return 0;
    }

    rctx->state = IDLE;
    init_waitqueue_head(&rctx->sem);

    rctx->cm_id = rdma_create_id(&init_net, cm_event_handler, rctx, RDMA_PS_TCP,
            IB_QPT_RC);
    if (IS_ERR(rctx->cm_id)) {
        r = PTR_ERR(rctx->cm_id);
        pr_err("%s,rdma_create_id error: %d\n", __func__, r);
    }

    in4_pton(rctx->addr_str, -1, rctx->addr, -1, NULL);
    /* Coperd: bind to local RDMA dev */
    fill_sockaddr(&sin, rctx);

    r = rdma_resolve_addr(rctx->cm_id, NULL, (struct sockaddr *)&sin, 2000);
    if (r) {
        pr_err("%s,rdma_resolve_addr error:%d\n", __func__, r);
        return r;
    }

    /* Coperd: need to wait here until ROUTE_RESOLVED */
    wait_event_interruptible_timeout(rctx->sem, rctx->state >= ROUTE_RESOLVED,
            msecs_to_jiffies(500));
    if (rctx->state != ROUTE_RESOLVED) {
        pr_err("%s,route not resolved!\n", __func__);
        return -EINTR;
    }

    if (!reg_supported(rctx->cm_id->device)) {
        pr_err("Coperd,RDMA dev doesn't support mem reg\n");
        return -EINVAL;
    }

    r = setup_qp(rctx, rctx->cm_id);
    if (r) {
        pr_err("%s, setup_qp() failed:%d\n", __func__, r);
        return r;
    }

#if 0
    r = ib_post_recv(rctx->qp, &rctx->rq_wr, &bad_wr);
    if (r) {
        pr_err("Coperd,ib_post_recv failed: %d\n", r);
        return r;
    }
    printk("Coperd,posted a recv ..\n");
#endif

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.responder_resources = 0;
    conn_param.initiator_depth = 0;
    conn_param.retry_count = 0;
    r = rdma_connect(rctx->cm_id, &conn_param);
    if (r) {
        pr_err("%s,rdma_connect() failed:%d\n", __func__, r);
        return r;
    }

    printk("Coperd,waiting to be connected\n");
    wait_event_interruptible_timeout(rctx->sem, rctx->state >= CONNECTED,
            msecs_to_jiffies(500));
    if (rctx->state == ERROR) {
        pr_err("Coperd,rctx in error state!\n");
        return -1;
    }

    printk("Coperd,%s,rctx[%d], connected!\n", __func__, rctx->rid);

    return 0;
}

void wpt_rdma_deinit(struct rctx *rctx)
{
    pr_info("[LeapIO] rdma_disconnect\n");
    rdma_disconnect(rctx->cm_id);
    pr_info("[LeapIO] rdma_disconnect(ed)\n");

    pr_info("[LeapIO] ib_destroy_qp\n");
    ib_destroy_qp(rctx->qp);
    pr_info("[LeapIO] ib_destroy(ed)_qp\n");

    pr_info("[LeapIO] ib_destroy_cq\n");
    ib_destroy_cq(rctx->cq);
    pr_info("[LeapIO] ib_destroy(ed)_cq\n");

    pr_info("[LeapIO] ib_dealloc_pd\n");
    ib_dealloc_pd(rctx->pd);
    pr_info("[LeapIO] ib_dealloc(ed)_pd\n");

    pr_info("[LeapIO] rdma_destroy_id\n");
    rdma_destroy_id(rctx->cm_id);
    pr_info("[LeapIO] rdma_destroy(ed)_id\n");
}

int wpt_setup_wrs(struct rctx *rctx)
{
    struct ib_recv_wr *rwr;
    struct ib_send_wr *swr;
    struct ib_sge *sge;
    int i;

    rctx->sbuf = ib_dma_alloc_coherent(rctx->pd->device,
            NVME_CMD_SZ * NVME_CPL_DATA_CNT,
            &rctx->sbuf_dma_addr, GFP_KERNEL);
    if (!rctx->sbuf) {
        pr_err("Coperd,ib_dma_alloc_coherent failed for rctx[%d]\n", rctx->rid);
        return -ENOMEM;
    }

    rctx->rbuf = ib_dma_alloc_coherent(rctx->pd->device,
            NVME_CPL_DATA_SZ * NVME_CPL_DATA_CNT,
            &rctx->rbuf_dma_addr, GFP_KERNEL);

    if (!rctx->rbuf) {
        pr_err("Coperd,ib_dma_alloc_coherent failed for rctx[%d]\n", rctx->rid);
        return -ENOMEM;
    }

#if 0
    rctx->rbuf = kzalloc(NVME_CPL_DATA_SZ * NVME_CPL_DATA_CNT, GFP_KERNEL);

    if (!rctx->rbuf) {
        pr_err("Coperd,ib_dma_alloc_coherent failed for rctx[%d]\n", rctx->rid);
        return -ENOMEM;
    }

    rctx->rbuf_dma_addr = dma_map_single(&rctx->pd->device->dev, rctx->rbuf,
            NVME_CPL_DATA_SZ * NVME_CPL_DATA_CNT, DMA_BIDIRECTIONAL);
    pr_info("[LeapIO] finished dma_map_single\n");
#endif

    /* Once these rwr/swr are setup, we can directly use them in future */
    for (i = 0; i < NVME_CPL_DATA_CNT; i++) {
        /* For recv */
        rwr = &rctx->rwrs[i];
        sge = &rctx->rsges[i];

        /* Coperd: FIXME: need to use DMA addr in SGE here */
        sge->addr = (uintptr_t)rctx->rbuf_dma_addr + NVME_CPL_DATA_SZ * i;
        sge->length = NVME_CPL_DATA_SZ; //NVME_CPL_SZ;
        sge->lkey = rctx->pd->local_dma_lkey;

#if 0
        if (sge->length != 4112) {
            pr_info("this is error. length is %u\n", sge->length);
        }
#endif

        /* Coperd: kernel verbs have no opcode: IB_WR_SEND */
        rwr->wr_id = (u64)i; /* when recv WC, we can refer back to the buf */
        rwr->sg_list = sge;
        rwr->num_sge = 1;

        /* For send */
        swr = &rctx->swrs[i];
        sge = &rctx->ssges[i];

        sge->addr = (uintptr_t)rctx->sbuf_dma_addr + NVME_CMD_SZ * i;
        sge->length = NVME_CMD_SZ;
        sge->lkey = rctx->pd->local_dma_lkey;

        swr->wr_id = (uintptr_t)swr;
        swr->sg_list = sge;
        swr->num_sge = 1;
        swr->opcode = IB_WR_SEND;
        swr->send_flags = IB_SEND_SIGNALED;
        swr->next = NULL;
    }

    return 0;
}

int wpt_post_initial_recvs(struct rctx *rctx)
{
    struct ib_recv_wr *bad_wr;
    struct ib_recv_wr *rwr;
    int r;
    int i;

    for (i = 0; i < NVME_CPL_DATA_CNT; i++) {
        /* compose the wr first */
        rwr = &rctx->rwrs[i];

        r = ib_post_recv(rctx->qp, rwr, &bad_wr);
        if (r) {
            pr_err("Coperd,%s,ib_post_recv failed\n", __func__);
            /* TODO: error handling here */
        }
    }

    return 0;
}

void wpt_check_cmpls(struct rctx *rctx)
{
#ifndef USE_INT
	cq_event_handler(rctx->cq, rctx);
#endif
}
