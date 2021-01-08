/*
 * File wpt-qpmap.c
 *
 * LeapIO driver utilities for Queue Pair mapping across host/VM boundaries
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include "wpt.h"

/* Coperd: pointer to pQP buffer */
struct leap_qpbuf *qpbufp;

inline bool wpt_is_q_type_valid(struct wpt_qp_data *data)
{
    int qt = data->q_type;
    /* Coperd: WPT_DB_T is specifically for Shadow Doorbell */
    return (qt == WPT_DB_T || qt == WPT_SQ_T || qt == WPT_CQ_T);
}

int get_q_npages(struct wpt_qp_data *tdata)
{
    /* Coperd: # of PTEs needed to map */
    int npages = tdata->q_entry_sz * tdata->q_nr_entry / PAGE_SIZE;
    BUG_ON(npages < 0 || npages > WPT_Q_NPAGES);
    if (npages == 0)
        npages = 1;

    return npages;
}

inline bool wpt_is_q_sdb(struct wpt_qp_data *data)
{
    int qt = data->q_type;

    return (qt == WPT_DB_T);
}

int wpt_qpair_meta_init(struct wpt *wpt)
{
    int i;

    wpt->qpair_meta = kmalloc(sizeof(struct wpt_qpair_meta), GFP_KERNEL);
    if (!wpt->qpair_meta) {
        printk("Coperd,%s,kmalloc failed\n", __func__);
        return -1;
    }

    INIT_LIST_HEAD(&(wpt->qpair_meta->tomap_db));
    INIT_LIST_HEAD(&(wpt->qpair_meta->mapped_db));
    for (i = 0; i < WPT_Q_T_NUM; i++) {
        INIT_LIST_HEAD(&(wpt->qpair_meta->tomap[i]));
        INIT_LIST_HEAD(&(wpt->qpair_meta->mapped[i]));
    }

    return 0;
}

void wpt_qpair_meta_free(struct wpt_qpair_meta *qpair_meta)
{
    int i;
    struct wpt_qp *iter, *titer;
    struct list_head *lh;

    lh = &qpair_meta->tomap_db;
    list_for_each_entry_safe(iter, titer, lh, list) {
        kfree(iter->data);
        kfree(iter);
    }

    lh = &qpair_meta->mapped_db;
    list_for_each_entry_safe(iter, titer, lh, list) {
        kfree(iter->data);
        kfree(iter);
    }

    /* Coperd: free the list elements first */
    for (i = 0; i < WPT_Q_T_NUM; i++) {
        lh = &qpair_meta->tomap[i];
        list_for_each_entry_safe(iter, titer, lh, list) {
            kfree(iter->data);
            kfree(iter);
        }

        lh = &qpair_meta->mapped[i];
        list_for_each_entry_safe(iter, titer, lh, list) {
            kfree(iter->data);
            kfree(iter);
        }
    }

    if (qpair_meta) {
        kfree(qpair_meta);
    }
}

void dump_wpt_qp_data(struct wpt_qp_data *data)
{
    int i;
    int npages = data->q_entry_sz * data->q_nr_entry / PAGE_SIZE;
    if (npages == 0) npages = 1;
    for (i = 0; i < npages; i++) {
        printk("\nCoperd,queue pfn[%d]=%lx\n", i, data->q_baddr[i]);
    }
    printk("Coperd,queue entry_sz=%d\n", data->q_entry_sz);
    printk("Coperd,queue nr_entry=%d\n", data->q_nr_entry);
    printk("Coperd,queue id:%d\n", data->q_id);
    printk("Coperd,queue type:%d\n\n", data->q_type);
    printk("Coperd,QEMU VM pid:%d\n\n", data->vm_pid);
}

void print_nvmecmd(struct nvme_rw_cmd *c)
{
    printk("Coperd,opc:%d,flags:%d,cid:%d,nsid:%d,lba:%lld,len:%d,"
            "prp1:%llx,prp2:%llx,control:%d\n",
            c->opcode, c->flags, c->cid, c->nsid, le64_to_cpu(c->slba),
            le16_to_cpu(c->nlb) + 1, le64_to_cpu(c->dptr.prp.prp1),
            le64_to_cpu(c->dptr.prp.prp2), le16_to_cpu(c->control));
}

void print_completion(struct nvme_completion c)
{
    printk("Coperd,completion,sq_head=%d,sq_id=%d,cid=%d,status=%d\n",
            c.sq_head, c.sq_id, c.cid, c.status);
}

void print_nvmeq(struct leap_qpbuf *buf)
{
    printk("Coperd,sq_paddr=%llx,cq_paddr=%llx,db_paddr=%llx,depth=%d,"
            "stride=%d\n", buf->sq_paddr, buf->cq_paddr, buf->db_paddr,
            buf->q_depth, buf->stride);
}

struct leap_qpbuf *get_qpbuf(void)
{
    return qpbufp;
}

