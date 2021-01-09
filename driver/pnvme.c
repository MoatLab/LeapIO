/*
 * File pnvme.c
 * NVMe utilities for LeapIO ATS driver
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include "wpt.h"

bool nvme_sq_empty(struct nvme_qpair *qpair)
{
    return qpair->sq_head == qpair->sq_tail;
}

void nvme_ring_sq_doorbell(struct nvme_qpair *qpair)
{
    u16 tail = qpair->sq_tail;

    //pr_debug("Coperd,%s,before ring SQ-DB,tail=%d\n", __func__, tail);
    writel(tail, qpair->sq_db);
    //pr_debug("Coperd,%s,after ring SQ-DB,tail=%d\n", __func__, tail);
}

void nvme_ring_cq_doorbell(struct nvme_qpair *qpair)
{
    u16 head = qpair->cq_head;

    //pr_debug("Coperd,%s,ring CQ-DB,head=%d\n", __func__, head);
    writel(head, qpair->cq_db);
}

inline bool nvme_cqe_valid(struct nvme_qpair *qpair, u16 head, u16 phase)
{
    return (le16_to_cpu(qpair->cqes[head].status) & 1) == phase;
}

void nvme_submit_cmd(struct nvme_qpair *qpair, struct nvme_command *cmd)
{
    u16 tail = qpair->sq_tail;
    memcpy((void *)&qpair->sq_cmds[tail], cmd, sizeof(*cmd));

    //print_nvmecmd(cmd->c);

    if (++tail == qpair->q_depth)
        tail = 0;

    qpair->sq_tail = tail;

    /* Coperd: must come after sq_tail is set to newest tail position */
    nvme_ring_sq_doorbell(qpair);
}

inline bool nvme_read_cqe(struct nvme_qpair *qpair, struct nvme_completion *cqe)
{
    if (nvme_cqe_valid(qpair, qpair->cq_head, qpair->cq_phase)) {
        *cqe = qpair->cqes[qpair->cq_head];
        //print_completion(*cqe);

        if (++qpair->cq_head == qpair->q_depth) {
            qpair->cq_head = 0;
            qpair->cq_phase = !qpair->cq_phase;
        }
        return true;
    }

    return false;
}

inline void nvme_handle_cqe(struct nvme_qpair *qpair, struct nvme_completion *cqe)
{
    if (unlikely(cqe->cid >= qpair->q_depth)) {
        printk("Coperd, invalid id %d completed on queue %d\n", cqe->cid,
                le16_to_cpu(cqe->sq_id));
        return;
    }

    /* Coperd: embed corresponding processing logic here */
}

void nvme_process_cq(struct nvme_qpair *qpair)
{
    struct nvme_completion cqe;
    int consumed = 0;

    while (nvme_read_cqe(qpair, &cqe)) {
        nvme_handle_cqe(qpair, &cqe);
        consumed++;
    }

    if (consumed)
        nvme_ring_cq_doorbell(qpair);
}

int nvme_poll(struct nvme_qpair *qpair)
{
    struct nvme_completion cqe;
    int consumed = 0;

    if (!nvme_cqe_valid(qpair, qpair->cq_head, qpair->cq_phase)) {
        return 0;
    }

    //printk("Coperd,%s,about to handle a CQE\n", __func__);
    spin_lock_irq(&qpair->q_lock);
    while (nvme_read_cqe(qpair, &cqe)) {
        nvme_handle_cqe(qpair, &cqe);
        consumed++;
    }

    if (consumed) {
        //printk("Coperd,%s,before ring CQ-DB\n", __func__);
        nvme_ring_cq_doorbell(qpair);
        //printk("Coperd,%s,after ring CQ-DB\n", __func__);
    }
    spin_unlock_irq(&qpair->q_lock);

    return consumed;
}

void nvme_inc_sq_head(struct nvme_qpair *vqp)
{
    vqp->sq_head = (vqp->sq_head + 1) % vqp->q_depth;
}

void nvme_update_sq_tail(struct nvme_qpair *vqp)
{
    /* Coperd: shadow DB always contains the newest tail location */
    u16 tail;

    if (!vqp->is_active)
	    return;

    BUG_ON(!vqp->is_active);
    BUG_ON(!vqp->sq_db);
    BUG_ON(vqp->sq_tail < 0 || vqp->sq_tail >= vqp->q_depth);

    tail = *(vqp->sq_db);
    if (tail != vqp->sq_tail) {
        ats_debug("vSQ[%d] tail:%d\n", vqp->qid, tail);
        vqp->sq_tail = tail;
    }
}

void nvme_update_sq_tail_soc(struct nvme_qpair *vqp)
{
    /* Coperd: need atomic ops here ? */
    BUG_ON(vqp->sq_head < 0 || vqp->sq_head >= vqp->q_depth);

    smp_mb();

    *(vqp->sq_db_soc) = vqp->sq_head;
}

void nvme_inc_cq_tail(struct nvme_qpair *vqp)
{
    vqp->cq_tail++;
    if (vqp->cq_tail >= vqp->q_depth) {
        vqp->cq_tail = 0;
        vqp->cq_phase = !vqp->cq_phase;
    }
}

void nvme_cq_update_head(struct nvme_qpair *vqp)
{
    vqp->cq_head = *(vqp->cq_db);
    BUG_ON(vqp->cq_head < 0 || vqp->cq_head >= vqp->q_depth);
}

int nvme_cq_full(struct nvme_qpair *vqp)
{
    nvme_cq_update_head(vqp);

    return (vqp->cq_tail + 1) % vqp->q_depth == vqp->cq_head;
}

