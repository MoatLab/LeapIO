#include "qemu/osdep.h"
#include "block/block_int.h"
#include "block/qapi.h"
#include "exec/memory.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci.h"
#include "qapi/visitor.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/bitops.h"
#include "qemu/bitmap.h"
#include "qom/object.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include <qemu/main-loop.h>

#include "leap-nvme.h"

void leap_print_nvme_cmd(NvmeCmd *cmd)
{
    printf("Coperd,SQE,opcode:%d,fuse:%d,cid:%d,nsid:%d,prp1:0x%" PRIx64 ","
            "prp2:0x%" PRIx64 "\n", cmd->opcode, cmd->fuse, cmd->cid, cmd->nsid,
            cmd->prp1, cmd->prp2);
}

void leap_print_nvme_cqe(NvmeCqe *cqe)
{
    printf("Coperd,CQE,result:%"PRIu64",sq_head=%d,sq_id=%d,cid=%d,status=%d\n",
            cqe->res64, cqe->sq_head, cqe->sq_id, cqe->cid, cqe->status);
}

int leap_nvme_cmd_cmp(NvmeCmd *a, NvmeCmd *b)
{
    assert(a && b);

    if (a->opcode == b->opcode && a->fuse == b->fuse && a->cid == b->cid &&
            a->nsid == b->nsid && a->res1 == b->res1 && a->mptr == b->mptr &&
            a->prp1 == b->prp1 && a->prp2 == b->prp2 && a->cdw10 == b->cdw10 &&
            a->cdw11 == b->cdw11 && a->cdw12 == b->cdw12 && a->cdw13 == b->cdw13
            && a->cdw14 == b->cdw14 && a->cdw15 == b->cdw15)
        return 0;

    printf("Coperd,--cmd1--\n");
    leap_print_nvme_cmd(a);
    printf("Coperd,--cmd2--\n");
    leap_print_nvme_cmd(b);

    return -1;
}

int leap_nvme_cqe_cmp(NvmeCqe *a, NvmeCqe *b)
{
    assert(a && b);

    if (a->res64 == b->res64 && a->sq_head == b->sq_head && a->sq_id == b->sq_id
            && a->cid == b->cid && a->status == b->status)
        return 0;

    printf("Coperd,--cqe1--\n");
    leap_print_nvme_cqe(a);
    printf("Coperd,--cqe2--\n");
    leap_print_nvme_cqe(b);

    return -1;
}

int leap_qpbuf_init(NvmeCtrl *n)
{
    struct leap_qpbuf *qpbuf = &n->qpbuf;
    int ret = 0;

    qpbuf->sqdata = g_malloc0(sizeof(struct wpt_qp_data) * QEMU_NVME_MAX_NVQS);
    if (!qpbuf->sqdata) {
        printf("Coperd,qpbuf->sqdata allocation failed\n");
        ret = -1;
        return ret;
    }

    qpbuf->cqdata = g_malloc0(sizeof(struct wpt_qp_data) * QEMU_NVME_MAX_NVQS);
    if (!qpbuf->cqdata) {
        printf("Coperd,qpbuf->cqdata allocation failed\n");
        ret = -1;
        goto err_sqdata;
    }

    qpbuf->sq_baddr = g_malloc0(sizeof(uint64_t) * QEMU_NVME_MAX_NVQS);
    if (!qpbuf->sq_baddr) {
        printf("Coperd,qpbuf->sq_baddr allocation failed\n");
        ret = -1;
        goto err_cqdata;
    }

    qpbuf->sqsz = g_malloc0(sizeof(int) * QEMU_NVME_MAX_NVQS);
    if (!qpbuf->sqsz) {
        printf("Coperd,qpbuf->sqsz allocation failed\n");
        ret = -1;
        goto err_sqsz;
    }

    qpbuf->cq_baddr = g_malloc0(sizeof(uint64_t) * QEMU_NVME_MAX_NVQS);
    if (!qpbuf->cq_baddr) {
        printf("Coperd,qpbuf->cq_baddr allocation failed\n");
        ret = -1;
        goto err_cq_addr;
    }

    qpbuf->cqsz = g_malloc0(sizeof(int) * QEMU_NVME_MAX_NVQS);
    if (!qpbuf->cqsz) {
        printf("Coperd,qpbuf->cqsz allocation failed\n");
        ret = -1;
        goto err_cqsz;
    }

    qpbuf->sq_mapped = g_malloc0(sizeof(bool) * QEMU_NVME_MAX_NVQS);
    if (!qpbuf->sq_mapped) {
        printf("Coperd,qpbuf->sq_mapped allocation failed\n");
        ret = -1;
        goto err_sq_mapped;
    }

    qpbuf->cq_mapped = g_malloc0(sizeof(bool) * QEMU_NVME_MAX_NVQS);
    if (!qpbuf->cq_mapped) {
        printf("Coperd,qpbuf->cq_mapped allocation failed\n");
        ret = -1;
        goto err_cq_mapped;
    }

    qpbuf->dbs_addr = 0;
    qpbuf->eis_addr = 0;
    qpbuf->db_mapped = false;
    qpbuf->nvqs = QEMU_NVME_MAX_NVQS;

    /* Coperd: init pagemap fd for HVA->HPA translation */
    pagemap_fd = open(LEAP_PAGEMAP_SELF, O_RDONLY);
    if (pagemap_fd < 0) {
        printf("Coperd,%s,error open %s for HVA->HPA translation, errno(%d)",
                __func__, LEAP_PAGEMAP_SELF, errno);
        return -1;
    }
    printf("Coperd,open %s as FD[%d]\n", LEAP_PAGEMAP_SELF, pagemap_fd);

    return 0;

err_cq_mapped:
    g_free(qpbuf->sq_mapped);

err_sq_mapped:
    g_free(qpbuf->cqsz);

err_cqsz:
    g_free(qpbuf->cq_baddr);

err_cq_addr:
    g_free(qpbuf->sqsz);

err_sqsz:
    g_free(qpbuf->sq_baddr);

err_cqdata:
    g_free(qpbuf->cqdata);

err_sqdata:
    g_free(qpbuf->sqdata);

    return ret;
}

int leap_qpbuf_free(NvmeCtrl *n)
{
    struct leap_qpbuf *qpbuf = &n->qpbuf;

    g_free(qpbuf->sqdata);
    g_free(qpbuf->cqdata);
    g_free(qpbuf->sq_mapped);
    g_free(qpbuf->cq_mapped);
    g_free(qpbuf->sq_baddr);
    g_free(qpbuf->cq_baddr);
    g_free(qpbuf->sqsz);
    g_free(qpbuf->cqsz);

    return 0;
}

NvmeCmd *leap_qpbuf_get_sqe(NvmeCtrl *n, int sqid, int sq_head)
{
    struct leap_qpbuf *qpbuf = &n->qpbuf;

    NvmeCmd *sqb = (NvmeCmd *)(qpbuf->sq_baddr[sqid]);
    if (!sqb) {
        return NULL;
    }

    return (NvmeCmd *)(&(sqb[sq_head]));
}

NvmeCqe *leap_qpbuf_get_cqe(NvmeCtrl *n, int cqid, int cq_tail)
{
    struct leap_qpbuf *qpbuf = &n->qpbuf;

    NvmeCqe *cqb = (NvmeCqe *)(qpbuf->cq_baddr[cqid]);
    if (!cqb) {
        return NULL;
    }

    return (NvmeCqe *)(&(cqb[cq_tail]));
}

void leap_qpbuf_debug_cqe(NvmeCQueue *cq, NvmeCqe *qcqe)
{
    NvmeCtrl *n = cq->ctrl;
    NvmeCqe *cqe;
    int ret;

    cqe = leap_qpbuf_get_cqe(n, cq->cqid, cq->tail);
    if (!cqe) {
        printf("Coperd,%s,ERROR! Leap qpbuf failed to get CQE at CQ[%d,%d]!\n",
                __func__, cq->cqid, cq->tail);
        return;
    }

    printf("Coperd,CQ[%d,%d],", cq->cqid, cq->tail);
    leap_print_nvme_cqe(qcqe);
    ret = leap_nvme_cqe_cmp(qcqe, cqe);
    if (ret != 0) {
        exit(EXIT_FAILURE);
    }
}

int leap_qpbuf_register_sq(NvmeSQueue *sq)
{
    struct NvmeCtrl *n = sq->ctrl;
    struct leap_qpbuf *qpbuf = &n->qpbuf;
    int sqid = sq->sqid;
    int size = sq->size;
    hwaddr sqsz = sizeof(NvmeCmd) * size;
    hwaddr qsz = sqsz;
    uint64_t saddr, eaddr;
    uint64_t addr;
    uint64_t sq_hfn;
    int i;

    struct wpt_qp_data sqdata = {
        .q_entry_sz = sizeof(NvmeCmd),
        .q_nr_entry = size,
        .q_id = sqid,
        .q_type = WPT_SQ_T,
        .vm_pid = getpid()
    };

    if (qpbuf->sq_mapped[sqid] == true) {
        printf("Coperd,%s,WARNING,SQ[%d] HVA already mapped\n", __func__, sqid);
        leap_qpbuf_unregister_sq(sq);
    }

    assert(qpbuf->sq_mapped[sqid] == false);
    printf("Coperd,Leap:mapping SQ[%d] buffer [GPA->HVA]\n", sqid);
    qpbuf->sq_baddr[sqid] =
        (uint64_t)cpu_physical_memory_map((hwaddr)sq->dma_addr, &sqsz, 0);
    if (!((void *)(qpbuf->sq_baddr[sqid])) || (sqsz != qsz)) {
        printf("Coperd,%s,map SQ[%d] to QEMU space failed\n", __func__, sqid);
        exit(EXIT_FAILURE);
    }

    printf("Coperd,SQ[%d] HVA:%"PRIu64"\n", sqid, qpbuf->sq_baddr[sqid]);
    qpbuf->sqsz[sqid] = sqsz;

    saddr = qpbuf->sq_baddr[sqid];
    eaddr = qpbuf->sq_baddr[sqid] + sqsz;

    assert(n->page_size == 4096);
    for (addr = saddr, i = 0; addr < eaddr; addr += n->page_size, i++) {
        assert((addr & (n->page_size - 1)) == 0);
        sq_hfn = leap_hva2hfn((void *)addr);
        if (sq_hfn == LEAP_INVALID_PFN) {
            printf("Coperd,%s,Leap: No SQ[%d] HFN found\n", __func__, sqid);
            exit(EXIT_FAILURE);
        }
        sqdata.q_baddr[i] = sq_hfn;
    }

    if (n->leap_qp_mapping) {
        printf("Coperd,Leap:register SQ[%d] info to WPT\n", sqid);
        leap_do_wpt_ioctl_reg(&sqdata);
    }
    qpbuf->sq_mapped[sqid] = true;

    return 0;
}

void leap_qpbuf_unregister_sq(NvmeSQueue *sq)
{
    NvmeCtrl *n = sq->ctrl;
    struct leap_qpbuf *qpbuf = &n->qpbuf;
    int sqid = sq->sqid;
    int size = sq->size;
    hwaddr sqsz = sizeof(NvmeCmd) * size;

    struct wpt_qp_data sqdata = {
        .q_entry_sz = sizeof(NvmeCmd),
        .q_nr_entry = size,
        .q_id = sqid,
        .q_type = WPT_SQ_T,
        .vm_pid = getpid()
    };

    assert(qpbuf->sq_mapped[sqid] == true);
    /* Coperd: unreg SQ from WPT */
    if (n->leap_qp_mapping) {
        printf("Coperd,Leap:unregister SQ[%d] info from WPT\n", sqid);
        leap_do_wpt_ioctl_unreg(&sqdata);
    }

    printf("Coperd,Leap:unmapping SQ[%d] buffer HVA\n", sqid);
    cpu_physical_memory_unmap((void *)qpbuf->sq_baddr[sqid], sqsz, 0, sqsz);
    qpbuf->sq_mapped[sqid] = false;
}

int leap_qpbuf_register_db(NvmeCtrl *n)
{
    struct leap_qpbuf *qpbuf = &n->qpbuf;
    struct wpt_qp_data *sdbdata = &qpbuf->sdbdata;
    hwaddr sdbsz = n->page_size;
    hwaddr dbsz = sdbsz;
    uint64_t db_hfn;

    sdbdata->q_entry_sz = sdbsz;
    sdbdata->q_nr_entry = 1;
    sdbdata->q_id = n->db_stride; /* Coperd: reuse q_id as stride for Shadow DB */
    sdbdata->q_type = -1; /* Coperd: use -1 to indicate this is shadow DB page */
    sdbdata->vm_pid = getpid();

    if (qpbuf->db_mapped == true) {
        printf("Coperd,%s,WARNING,ShadowDB HVA already mapped, unreg first\n",
                __func__);
        //leap_qpbuf_unregister_db(n);
    }

    assert(n->page_size == 4096);
    //assert(qpbuf->db_mapped == false);
    printf("Coperd,Leap:mapping shadowDB buffer [GPA->HVA]\n");
    qpbuf->dbs_addr = (uint64_t)cpu_physical_memory_map(n->dbs_addr, &sdbsz, 0);
    if (!((void *)(qpbuf->dbs_addr)) || (sdbsz != dbsz)) {
        printf("Coperd,%s,map shadowDB to QEMU space failed\n", __func__);
        exit(EXIT_FAILURE);
    }
    printf("Coperd,%s,shadowDB HVA:%"PRIu64"\n", __func__, qpbuf->dbs_addr);

    db_hfn = leap_hva2hfn((void *)qpbuf->dbs_addr);
    if (db_hfn == LEAP_INVALID_PFN) {
        printf("Coperd,%s,Leap: No Shadow DB HFN found\n", __func__);
        exit(EXIT_FAILURE);
    }
    sdbdata->q_baddr[0] = db_hfn;

    if (n->leap_qp_mapping) {
        printf("Coperd,Leap:register shadow Doorbell info to WPT\n");
        leap_do_wpt_ioctl_reg(sdbdata);
    }
    qpbuf->db_mapped = true;

    return 0;
}

void leap_qpbuf_unregister_db(NvmeCtrl *n)
{
    struct leap_qpbuf *qpbuf = &n->qpbuf;
    struct wpt_qp_data *sdbdata = &qpbuf->sdbdata;
    hwaddr sdbsz = n->page_size;

    assert(qpbuf->db_mapped == true);
    /* Coperd: unreg shadowDB from WPT */
    if (n->leap_qp_mapping) {
        printf("Coperd,Leap:unregister shadow Doorbell info from WPT\n");
        leap_do_wpt_ioctl_unreg(sdbdata);
    }

    printf("Coperd,Leap:unmapping shadowDB buffer HVA\n");
    cpu_physical_memory_unmap((void *)qpbuf->dbs_addr, sdbsz, 0, sdbsz);
    qpbuf->db_mapped = false;
}

int leap_qpbuf_register_cq(NvmeCQueue *cq)
{
    NvmeCtrl *n = cq->ctrl;
    struct leap_qpbuf *qpbuf = &n->qpbuf;
    int cqid = cq->cqid;
    int size = cq->size;
    hwaddr cqsz = sizeof(NvmeCqe) * size;
    hwaddr qsz = cqsz;
    uint64_t saddr, eaddr;
    uint64_t addr;
    uint64_t cq_hfn;
    int i;

    struct wpt_qp_data cqdata = {
        .q_entry_sz = sizeof(NvmeCqe),
        .q_nr_entry = size,
        .q_id = cqid,
        .q_type = WPT_CQ_T,
        .vm_pid = getpid(),
        .guest_notifier_fd = event_notifier_get_fd(&cq->guest_notifier)
    };

    if (qpbuf->cq_mapped[cqid] == true) {
        printf("Coperd,%s,WARNING,CQ[%d] HVA already mapped\n", __func__, cqid);
        leap_qpbuf_unregister_cq(cq);
    }

    assert(qpbuf->cq_mapped[cqid] == false);
    printf("Coperd,Leap:mapping CQ[%d] buffer [GPA->HVA]\n", cqid);
    qpbuf->cq_baddr[cqid] =
        (int64_t)cpu_physical_memory_map(cq->dma_addr, &cqsz, 0);
    if (!((void *)(qpbuf->cq_baddr[cqid])) || (cqsz != qsz)) {
        printf("Coperd,%s,map CQ[%d] to QEMU space failed\n", __func__, cqid);
        exit(EXIT_FAILURE);
    }
    printf("Coperd,CQ[%d] HVA:%"PRIu64"\n", cqid, qpbuf->cq_baddr[cqid]);
    qpbuf->cqsz[cqid] = cqsz;

    saddr = qpbuf->cq_baddr[cqid];
    eaddr = qpbuf->cq_baddr[cqid] + cqsz;

    assert(n->page_size == 4096);
    for (addr = saddr, i = 0; addr < eaddr; addr += n->page_size, i++) {
        assert((addr & (n->page_size - 1)) == 0);
        cq_hfn = leap_hva2hfn((void *)addr);
        if (cq_hfn == LEAP_INVALID_PFN) {
            printf("Coperd,%s,Leap: No CQ[%d] HFN found\n", __func__, cqid);
            exit(EXIT_FAILURE);
        }
        cqdata.q_baddr[i] = cq_hfn;
    }

    if (n->leap_qp_mapping) {
        printf("Coperd,register CQ[%d] data to WPT\n", cqid);
        leap_do_wpt_ioctl_reg(&cqdata);
    }
    qpbuf->cq_mapped[cqid] = true;

    return 0;
}

void leap_qpbuf_unregister_cq(NvmeCQueue *cq)
{
    NvmeCtrl *n = cq->ctrl;
    struct leap_qpbuf *qpbuf = &n->qpbuf;
    int cqid = cq->cqid;
    int size = cq->size;
    hwaddr cqsz = sizeof(NvmeCqe) * size;

    struct wpt_qp_data cqdata = {
        .q_entry_sz = sizeof(NvmeCqe),
        .q_nr_entry = size,
        .q_id = cqid,
        .q_type = WPT_CQ_T,
        .vm_pid = getpid()
    };

    assert(qpbuf->cq_mapped[cqid] == true);
    if (n->leap_qp_mapping) {
        printf("Coperd,Leap:unregister CQ[%d] info from WPT\n", cqid);
        leap_do_wpt_ioctl_unreg(&cqdata);
    }

    printf("Coperd,Leap:unmapping CQ[%d] buffer HVA\n", cqid);
    cpu_physical_memory_unmap((void *)qpbuf->cq_baddr[cqid], cqsz, 0, cqsz);
    qpbuf->cq_mapped[cqid] = false;
}
