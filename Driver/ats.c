/*
 * File ats.c
 *
 * Address Translation Service for VM IO requests submitted to and handled by
 * the SoC offloading engine.
 *
 * Terms: GPA -> Guest Physical Address, HVA -> Host Virtual Address, HPA ->
 * Host Physical Address
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include "wpt.h"
#include "globals.h"

#include <uapi/linux/sched/types.h>
#include <linux/kvm.h>
#include <linux/kvm_types.h>
#include <asm/kvm_host.h>
#include <linux/kvm_host.h>
#include <linux/nmi.h>
#include <linux/sched.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/sched/signal.h>

//#undef ATS_DEBUG

int wpt_follow_phys(struct mm_struct *mm, unsigned long address, u64 *phys);

static bool memslot_is_readonly(struct kvm_memory_slot *slot)
{
    return slot->flags & KVM_MEM_READONLY;
}

static unsigned long __gfn_to_hva_many(struct kvm_memory_slot *slot, gfn_t gfn,
				       gfn_t *nr_pages, bool write)
{
    if (!slot || slot->flags & KVM_MEMSLOT_INVALID) {
        pr_err("Coperd,%s,KVM_MEMSLOT_INVALID\n", __func__);
        return KVM_HVA_ERR_BAD;
    }

    if (memslot_is_readonly(slot) && write) {
        pr_err("Coperd,%s,KVM_HVA_ERR_RO_BAD\n", __func__);
        return KVM_HVA_ERR_RO_BAD;
    }

    if (nr_pages)
        *nr_pages = slot->npages - (gfn - slot->base_gfn);

    return __gfn_to_hva_memslot(slot, gfn);
}

/* Coperd: only for read PTE */
kvm_pfn_t gfn2pfn(struct kvm *kvm, gfn_t gfn)
{
    struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);
    pte_t *ptep;
    kvm_pfn_t pfn;

    bool write_fault = true;

    unsigned long addr = __gfn_to_hva_many(slot, gfn, NULL, write_fault);

    ptep = va2pte(kvm->mm, addr);
    if (!ptep) {
        return WPT_INVALID_PFN;
    }

    pfn = pte_pfn(*ptep);
    pte_unmap(ptep);
    ats_debug("gfn:%llx,hva:%lx,pfn:%llx\n", gfn, addr, pfn);

    return pfn;
}

u64 gpa2hpa(struct kvm *kvm, u64 gpa)
{
    u64 hpa;
    u64 gfn = gpa >> PAGE_SHIFT;
    unsigned long offset = gpa & ~PAGE_MASK;
    struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);
    unsigned long hva = __gfn_to_hva_many(slot, gfn, NULL, true);

    hva |= offset;
    hpa = hva2hpa(kvm->mm, hva);
    ats_debug("Coperd,%s,gfn:0x%llx,hva:0x%lx,hpa:0x%llx\n", __func__,
            gfn, hva, hpa);

    return hpa;
}

int wpt_do_cmd_ats(unsigned long arg)
{
    int ret = 0;
    struct ats_data *data;
    struct kvm *kvm;
    kvm_pfn_t pfn;
    ktime_t st, et;

    data = kmalloc(sizeof(*data), GFP_KERNEL);
    if (!data) {
        return -ENOMEM;
    }

    if (copy_from_user(data, (void __user *)arg, sizeof(*data))) {
        ret = -EFAULT;
        goto err_copy_from_user;
    }

    st = ktime_get();
    list_for_each_entry(kvm, &vm_list, vm_list) {
        if (kvm->userspace_pid == data->pid) {
            pfn = gfn2pfn(kvm, data->addr >> PAGE_SHIFT);
            et = ktime_get();
            ats_debug("pid:%d,time:%lld us\n", data->pid,
                    ktime_to_us(ktime_sub(et, st)));
            return 0;
        }
    }
    return 0;

err_copy_from_user:
    kfree(data);
    return -1;
}

static inline u32 get_si(struct nvme_qpair *vqp)
{
    return (u32)(*(vqp->si_db));
}

/* Coperd: whether to send an interrupt to guest */
static bool ats_should_notify(struct nvme_qpair *vqp)
{
    bool ret;
    u32 cur_si = get_si(vqp);
    ret = (vqp->prev_si != cur_si);
    vqp->prev_si = cur_si;

    return ret;
}

static void ats_signal(struct nvme_qpair *vqp)
{
    if (vqp->guest_notifier_ctx && ats_should_notify(vqp)) {
        eventfd_signal(vqp->guest_notifier_ctx, 1);
    }
}

int ats_should_do_ats(struct nvme_qpair *vqp)
{
    if (vqp->is_active && !nvme_sq_empty(vqp)) {
        return 1;
    }

    return 0;
}

static inline u64 get_nvme_cmd_prp1(struct nvme_command *cmd)
{
    return le64_to_cpu(cmd->rw.dptr.prp.prp1);
}

static inline int set_nvme_cmd_prp1(struct nvme_command *cmd, u64 val)
{
    cmd->rw.dptr.prp.prp1 = cpu_to_le64(val);

    return 0;
}

static inline int ats_mark_ats_done(struct nvme_command *cmd)
{
    cmd->rw.rsvd2 = 1;

    return 0;
}

inline u64 ats_do_ats_one_addr(struct kvm *kvm, u64 gpa)
{
    u64 hpa = gpa2hpa(kvm, gpa);

    if (hpa == WPT_INVALID_PFN || hpa == 0) {
        ats_err("ERROR,ATS failed for GPA:%llx,hpa=0x%llx\n", gpa, hpa);
        return WPT_INVALID_PFN;
    }

    return hpa;
}

static inline int ats_do_ats_vqp_cmd_prp1(struct kvm *kvm,
        struct nvme_command *cmd)
{
    u64 prp1 = le64_to_cpu(cmd->rw.dptr.prp.prp1);
    u64 prp1_hpa = ats_do_ats_one_addr(kvm, prp1);
    if (prp1_hpa == WPT_INVALID_PFN) {
        return -1;
    }
    cmd->rw.dptr.prp.prp1 = cpu_to_le64(prp1_hpa);
    //pr_info("this prp1 %llu, CID %d\n", cmd->rw.dptr.prp.prp1, cmd->rw.cid);

    return 0;
}

static inline int ats_do_ats_vqp_cmd_prp2(struct kvm *kvm, struct nvme_command *cmd)
{
    u64 prp2 = le64_to_cpu(cmd->rw.dptr.prp.prp2);
    u64 prp2_hpa = ats_do_ats_one_addr(kvm, prp2);
    if (prp2_hpa == WPT_INVALID_PFN) {
        return -1;
    }
    cmd->rw.dptr.prp.prp2 = cpu_to_le64(prp2_hpa);

    return 0;
}

int ats_do_ats_vqp_cmd_prp_all(struct kvm *kvm, struct nvme_command *cmd)
{
    u8 opc = cmd->rw.opcode;
    u64 prp1 = le64_to_cpu(cmd->rw.dptr.prp.prp1);
    u64 prp2 = le64_to_cpu(cmd->rw.dptr.prp.prp2);
    u64 slba = le64_to_cpu(cmd->rw.slba);
    u16 nlb = le16_to_cpu(cmd->rw.nlb) + 1;
    struct wpt *wpt = WPT();
    int len = nlb << wpt->data_shift;
    int ret;

    int cmax_prps = wpt->mdts / 512 + 1;

    /* Coperd: TODO: read this info from vNVMe controller later */
    int cpgsz = 4096;
    int cpgbits = 12;
    int max_prp_ents = 512; /* cpgsz / sizeof(u64); */
    int trans_len = cpgsz - (prp1 % cpgsz);
    int num_prps = (len >> cpgbits) + 1;

    void *prp_list_base;
    u64 *prp_list = NULL; /* [max_prp_ents] */
    struct page *prps_page = NULL;
    int nents, prp_trans;
    u64 prps_hpa, hpa;
    int i = 0;

    /* Coperd: OCSSD erase command doesn't carry any PRPs */
    if (opc == NVM_OP_ERASE) {
        return 0;
    }

    trans_len = min(len, trans_len);

    WARN_ONCE(num_prps > cmax_prps, "Invalid # of PRPs in vcmd");
    WARN_ON(slba < 0);
    ats_debug("prp1=%llx,prp2=%llx,slba=%llu,nlb=%d, data_size=%d,num_prps=%d\n",
            prp1, prp2, slba, nlb, len, num_prps);
    /* print_nvmecmd(&cmd->rw); */

    if (!prp1) {
        ats_err("prp1 = 0\n");
        print_nvmecmd(&cmd->rw);
        return -1;
    }

    /* Coperd: translate prp1 first, do it in place */
    ret = ats_do_ats_vqp_cmd_prp1(kvm, cmd);
    if (ret) {
        ats_err("prp1 translation failed\n");
        goto err;
    }
    len -= trans_len;

    /* Coperd: only 1 prp entry, we're done here */
    if (!len) {
        ats_mark_ats_done(cmd);
        return 0;
    }

    if (!prp2) {
        ats_err("prp2 = 0, rlen=%d\n", len);
        goto err;
    }

    /* Coperd: Need to read the PRP2 memory page */
    ret = ats_do_ats_vqp_cmd_prp2(kvm, cmd);
    if (ret) {
        ats_err("prp2 translation failed\n");
        goto err;
    }

    /* Coperd: only 2 prp ents, handle prp2 and then we're done */
    if (len <= cpgsz) {
        /* Coperd: according to NVMe spec, prp2 offset must be ZERO */
        if (prp2 & (cpgsz - 1)) {
            ats_err("prp2-offset != 0\n");
            goto err;
        }
        /* Coperd: in total 2 prps, we're done once prp2 is translated */
        ats_mark_ats_done(cmd);
        return 0;
    }

    /* Coperd: handle >=3 prps cases */
    nents = (len + cpgsz - 1) >> cpgbits;
    prp_trans = min(max_prp_ents, nents) * sizeof(u64);
    prps_hpa = le64_to_cpu(cmd->rw.dptr.prp.prp2);
    prps_page = pfn_to_page(prps_hpa >> PAGE_SHIFT);
    prp_list_base = vmap(&prps_page, 1, VM_MAP, PAGE_KERNEL_NOCACHE);
    prp_list = (u64 *)(prp_list_base + (prps_hpa & (~PAGE_MASK)));
    while (len != 0) {
        u64 prp_ent = le64_to_cpu(prp_list[i]);
        ats_debug("%d,i=%d,prp-gpa=%llx\n", __LINE__, i, prp_ent);

        /* Coperd: last ent in prp_list is a pointer to another prp list page */
        if (i == max_prp_ents - 1 && len > cpgsz) {
            if (!prp_ent || prp_ent & (cpgsz - 1)) {
                ats_err("secondary prp page\n");
                goto err;
            }
            i = 0;
            nents = (len + cpgsz - 1) >> cpgbits;
            prp_trans = min(max_prp_ents, nents) * sizeof(u64);
            /* Coperd: Need to read further PRP list page */
            vunmap(prp_list_base);
            prps_hpa = ats_do_ats_one_addr(kvm, prp_ent);
            if (prps_hpa == WPT_INVALID_PFN) {
                ats_err("ats failed for [%d]:%llx\n", i, prp_ent);
                goto err;
            }
            prps_page = pfn_to_page(prps_hpa >> PAGE_SHIFT);
            prp_list_base = vmap(&prps_page, 1, VM_MAP, PAGE_KERNEL_NOCACHE);
            prp_list = (u64 *)(prp_list_base + (prps_hpa & (~PAGE_MASK)));
            prp_ent = le64_to_cpu(prp_list[i]);
        }

        if (!prp_ent || prp_ent & (cpgsz - 1)) {
            ats_err("wrong prp_ent: %llx\n", prp_ent);
            goto err;
        }

        trans_len = min(len, cpgsz);
        /* Coperd: update prp_ent to HPA in place */
        hpa = ats_do_ats_one_addr(kvm, prp_ent);
        if (hpa == WPT_INVALID_PFN || hpa == 0) {
            ats_err("ats failed for [%d]:%llx\n", i, prp_ent);
            /* Coperd: ok, we try to continue here, TODO TODO */
        }
        prp_list[i] = cpu_to_le64(hpa);
        ats_debug("%d,i=%d,prp-hpa=%llx\n", __LINE__, i, prp_list[i]);
        len -= trans_len;
        i++;
    }

    if (prp_list) {
        vunmap(prp_list_base);
    }

    ats_mark_ats_done(cmd);
    return 0;

err:
    ats_debug("after: ");
    print_nvmecmd(&cmd->rw);
    return -1;
}

static inline bool is_ocrw_cmd(struct nvme_command *cmd)
{
    struct nvme_ocrw_cmd *ocrw = &cmd->ocrw;
    u8 opc = ocrw->opcode;

    if (opc != NVM_OP_PREAD && opc != NVM_OP_PWRITE && opc != NVM_OP_ERASE) {
        return false;
    }

    return true;
}

/* Coperd: only for OCSSD commands, otherwise do nothing */
static int ats_do_ats_vqp_cmd_meta(struct kvm *kvm, struct nvme_command *cmd)
{
    struct nvme_ocrw_cmd *ocrw = &cmd->ocrw;
    u64 md, md_hpa;

    if (!is_ocrw_cmd(cmd)) {
        return 0;
    }

    md = le64_to_cpu(ocrw->metadata);
    /* Coperd: allow users to not pass metadata for OCSSD command */
    if (md == 0) {
        return 0;
    }

    md_hpa = ats_do_ats_one_addr(kvm, md);
    if (md_hpa == WPT_INVALID_PFN) {
        return -1;
    }

    ocrw->metadata = cpu_to_le64(md_hpa);

    return 0;
}

static int ats_do_ats_vqp_cmd_ppalist(struct kvm *kvm, struct nvme_command *cmd)
{
    struct nvme_ocrw_cmd *ocrw = &cmd->ocrw;
    u64 spba = le64_to_cpu(ocrw->spba);
    u32 nppa = le16_to_cpu(ocrw->nlb) + 1;
    u64 spba_hpa;

    if (!is_ocrw_cmd(cmd)) {
        return 0;
    }

    if (nppa == 1) {
        return 0;
    }

    /* Coperd: nppa > 1, spba is a pointer to PPA list */
    spba_hpa = ats_do_ats_one_addr(kvm, spba);
    if (spba_hpa == WPT_INVALID_PFN) {
        return -1;
    }

    ocrw->spba = cpu_to_le64(spba_hpa);

    return 0;
}

/* Coperd: assume it's regular NVMe command for now */
int ats_do_ats_vqp_cmd(struct kvm *kvm, struct nvme_command *cmd)
{
    int ret = ats_do_ats_vqp_cmd_prp_all(kvm, cmd);

    /* Coperd: TODO: more error handling needed here */
    if (ret) {
        ats_err("PRP GPA->HPA failed\n");
    }

    /* Coperd: perform ATS for metadata buf and ppalist in OCSSD command */
    ret = ats_do_ats_vqp_cmd_meta(kvm, cmd);
    if (ret) {
        ats_err("META GPA->HPA failed\n");
    }

    ret = ats_do_ats_vqp_cmd_ppalist(kvm, cmd);
    if (ret) {
        ats_err("PPALIST GPA->HPA failed\n");
    }

    return 0;
}

void ats_fake_cqe(struct nvme_qpair *vqp, u16 cid)
{
    struct nvme_completion cqe;

    if (nvme_cq_full(vqp)) {
        /* Coperd: what to do here ? */
        ats_err("vCQ[%d] full, skipping CQE\n", vqp->qid);
        return;
    }

    /* Coperd: always fake SUCCESS completion */
    cqe.status = (0 << 1) | vqp->cq_phase;
    cqe.sq_id = vqp->qid;
    cqe.sq_head = vqp->sq_head;
    cqe.cid = cid;

    memcpy((void *)&vqp->cqes[vqp->cq_tail], &cqe, sizeof(cqe));
    ats_debug("vCQ[%d,%d]\n", vqp->qid, vqp->cq_tail);

    nvme_inc_cq_tail(vqp);
}

static bool is_valid_reg_nvme_rwcmd(struct nvme_command *cmd)
{
    u8 opc = cmd->rw.opcode;

    /* 0: flush, 1: write, 2: read for regular NVMe commands */
    if (opc == NVME_CMD_FLUSH || opc == NVME_CMD_WRITE || opc == NVME_CMD_READ)
        return true;

    return false;
}

static bool is_valid_oc_nvme_rwcmd(struct nvme_command *cmd)
{
    u8 opc = cmd->rw.opcode;

    /* Coperd: OC rw commands: read/write/erase */
    if (opc == NVM_OP_PREAD || opc == NVM_OP_PWRITE || opc == NVM_OP_ERASE)
        return true;

    return false;
}

static inline bool nvme_cmd_valid(struct nvme_command *cmd)
{
    u32 nsid = le32_to_cpu(cmd->rw.nsid);

    if (nsid != 1)
        return false;

    if (is_valid_reg_nvme_rwcmd(cmd) || is_valid_oc_nvme_rwcmd(cmd))
        return true;

    return false;
}

/* Coperd: mock NVMe controller SQ processing logic, we do ATS here */
int ats_do_ats_vqp(struct nvme_qpair *vqp)
{
    struct kvm *kvm = vqp->kvm;
    struct nvme_command *cmd;
    int cid;

    /* Coperd: do the validaty again */
    while (vqp->is_active && !nvme_sq_empty(vqp)) {
        /* Coperd: move forward from head -> tail */
        cmd = (struct nvme_command *)&vqp->sq_cmds[vqp->sq_head];
        if (!nvme_cmd_valid(cmd)) {
            print_nvmecmd(&cmd->rw);
            BUG();
        }
        ats_debug("vqp[%d] Loc[%d] ... ", vqp->qid, vqp->sq_head);
#ifdef ATS_DEBUG
        print_nvmecmd(&cmd->rw);
#endif
        cid = cmd->rw.cid;
        ats_do_ats_vqp_cmd(kvm, cmd);

        if (use_rdma_for_vqp) {
            struct rctx *rctx = vqp->rctx;
            struct ib_send_wr *swr = &rctx->swrs[cid];
            struct ib_send_wr *bad_wr;
            /*
             * Coperd: we already do swr init at the very beginning, just use it
             * here directly
             */
            memcpy(&((struct nvme_command *)rctx->sbuf)[cid], cmd, NVME_CMD_SZ);
#ifdef RDMA_DEBUG
            print_nvmecmd(&cmd->rw);
#endif
            ib_post_send(rctx->qp, swr, &bad_wr);
        }

        /* Coperd: if using RDMA for routing vQP, send cmd out now */

        /* Coperd: update sq_head */
        nvme_inc_sq_head(vqp);
        nvme_update_sq_tail_soc(vqp);

#ifdef ATS_FAKE_CQE
        /* Coperd: Fake a completion here, only for testing */
        if (vqp->should_do_fake_cqe)
            ats_fake_cqe(vqp, cmd->c.cid);
#endif
    }

    return 0;
}

u64 idle_poll = 0;
u64 npoll = 0;

int ats_do_ats(struct ats *ats)
{
    struct nvme_qpair *vqps = ats->vqps;
    /* int nr_vqps = 4; //ats->nr_vqps; */
    struct nvme_qpair *vqp;
    /* unsigned long flags; */
    int ret;
    int i;

    for (i = 0; i < MAX_VQPS/*nr_vqps*/; i++) {
        vqp = &vqps[i];
        BUG_ON(!vqp);
        npoll++;

        /* read_lock_irqsave(&vqp->q_rwlock, flags); */
        if (!vqp->is_active) {
            /* read_unlock_irqrestore(&vqp->q_rwlock, flags); */
            idle_poll++;
            continue;
        }

        /* Coperd: virq check */
        ats_signal(vqp);

        /* Coperd: for vSQ, refer to q_db (shadow) for newest tail */
        nvme_update_sq_tail(vqp);

        if (ats_should_do_ats(vqp)) {
            /* Coperd: just do it! */
            ret = ats_do_ats_vqp(vqp);
            if (ret) {
                /* read_unlock_irqrestore(&vqp->q_rwlock, flags); */
                continue;
            }
        } else {
            idle_poll++;
        }

        /* Check event completions. only if not using interrupts */
#ifdef RDMA_VQPS
        wpt_check_cmpls(vqp->rctx);
#endif

        /* read_unlock_irqrestore(&vqp->q_rwlock, flags); */
    }

    return 0;
}

int ats_ts(void *data)
{
    /* Coperd: let ATS rock with highest priority */
    /* struct sched_param param = {.sched_priority = MAX_RT_PRIO - 1}; */
    struct wpt *wpt = data;
    struct ats *ats = wpt->ats;

    allow_signal(SIGKILL);
    /* Coperd: use RT (w/ RR policy), depend on kernel sched throttling */
#if 0
    if (sched_setscheduler_nocheck(current, SCHED_RR, &param)) {
        pr_err("ERR,failed to set ATS priority to %d\n", param.sched_priority);
    }
#endif

    while (!kthread_should_stop()) {
        if (need_resched()) {
            /* Coperd: let the OS housekeeping run for a while */
            /* set_current_state(TASK_INTERRUPTIBLE); */
            schedule();
            /* set_current_state(TASK_RUNNING); */
        }

        if (signal_pending(ats->ats_ts))
            break;

        if (npoll >= 10000000) {
            usleep_range(1, 2);
            npoll = 0;
        }

        if (ats_do_ats(ats)) {
            /* Coperd: error handling? */
        }
    }

    if (use_rdma_for_vqp) {
        pr_info("Deallocating RDMA resources\n");
        wpt_deinit();
    }

    pr_info("ATS-poller exited ..\n");
    return 0;
}

static inline unsigned int sq_idx(unsigned int qid, u32 stride)
{
    return qid * 2 * stride;
}

static inline unsigned int sq_idx_soc(unsigned int qid, u32 stride)
{
    //int half_page = 2048;   // PAGE_SIZE / 2;
    int soc_oft = 256;      // half_page / (2 * sizeof(u32));

    return (qid + soc_oft) * 2 * stride;
}

int ats_unmap_dbbuf(struct wpt *wpt, int ats_qid)
{
    struct ats *ats = wpt->ats;
    int idx = ats_qid - 1;

    vunmap(ats->dbbuf[idx]);
    ats->dbbuf[idx] = NULL;

    return 0;
}

int ats_map_dbbuf(struct wpt *wpt, unsigned long dbpfn, int ats_qid)
{
    struct ats *ats = wpt->ats;
    int idx = ats_qid - 1;

    ats->dbpg[idx] = pfn_to_page(dbpfn);
    ats->dbbuf[idx] = vmap(&ats->dbpg[idx], 1, VM_MAP | VM_IOREMAP, PAGE_KERNEL_NOCACHE);
    if (!ats->dbbuf[idx]) {
        return -1;
    }

    return 0;
}

int ats_reinit_dbbuf(struct wpt *wpt, unsigned long dbpfn, int ats_qid)
{
    struct ats *ats = wpt->ats;
    int idx = ats_qid - 1;

    if (ats->dbbuf[idx]) {
        ats_unmap_dbbuf(wpt, ats_qid);
    }

    return ats_map_dbbuf(wpt, dbpfn, ats_qid);
}

int ats_init_vqp(struct wpt *wpt, struct nvme_qpair *vqp, int qid)
{
    vqp->is_active = false;

    vqp->qid = qid;
    vqp->q_depth = 256;

    vqp->sq_tail = 0;
    vqp->sq_head = 0;
    vqp->cq_tail = 0;
    vqp->cq_head = 0;
    vqp->cq_phase = 1;

    /* Coperd: various doorbells for VM/ATS/SoC communication */
    vqp->sq_db = NULL;
    vqp->cq_db = NULL;
    vqp->sq_db_soc = NULL;
    vqp->sp_db = &((wpt->spbuf)[qid]);
    vqp->si_db = &((wpt->sibuf)[qid]);

    vqp->vm_pid = -1;
    vqp->spdk_quirk = false;

    vqp->guest_notifier_filp = NULL;
    vqp->guest_notifier_ctx = NULL;

    //rwlock_init(&vqp->q_rwlock);

    return 0;
}

/* Coperd: set should-poll doorbell */
static inline void set_sp(volatile u8 *sp_db)
{
    *sp_db = 1;
    smp_mb();
}

static inline void clear_sp(volatile u8 *sp_db)
{
    *sp_db = 0;
    smp_mb();
}

int ats_disable_vqp(struct ats *ats, struct wpt_qp *qp)
{
    struct wpt *wpt = ats->wpt;
    struct nvme_qpair *vqp = ats_get_vqp(wpt, qp); //&ats->vqps[qid - 1];
    int qid = vqp->qid;
    //unsigned long flags;

    printk("[stnovako] disable QP with ID: %d\n", qid);

    //write_lock_irqsave(&vqp->q_rwlock, flags);
    if (!vqp->is_active) {
        ats_info("vqp[%d] already disabled\n", qid);
        //write_unlock_irqrestore(&vqp->q_rwlock, flags);
        return 0;
    }

    vqp->is_active = false;
    clear_sp(vqp->sp_db);
    *(vqp->sq_db) = 0;
    *(vqp->cq_db) = 0;
    *(vqp->sq_db_soc) = 0;

    vqp->nr_ready_res = 0;
    vqp->spdk_quirk = false;
    vqp->sq_tail = 0;
    vqp->sq_head = 0;
    vqp->cq_head = 0;
    vqp->cq_tail = 0;
    vqp->cq_phase = 1;
    vqp->q_depth = 256;
    vqp->qid = qid;

    if (vqp->cqes) {
        printk("[stnovako] unmap CQES\n");
        vunmap((void *)vqp->cqes);
        vqp->cqes = NULL;
    }
    if (vqp->sq_cmds) {
        printk("[stnovako] unmap SQCMDS\n");
        vunmap((void *)vqp->sq_cmds);
        vqp->sq_cmds = NULL;
    }
    /* stnovako */
    if (ats->dbbuf[qid - 1]) {
        printk("[stnovako] unmap DBbuf\n");
        ats_unmap_dbbuf(wpt, qid);
    }

    if (vqp->guest_notifier_ctx) {
        printk("[stnovako] notify guest\n");
        eventfd_ctx_put(vqp->guest_notifier_ctx);
    }
    if (vqp->guest_notifier_filp) {
        printk("[stnovako] norify guest filp\n");
        fput(vqp->guest_notifier_filp);
    }

    //write_unlock_irqrestore(&vqp->q_rwlock, flags);

    ats_info("vQP[%d] disabled\n", qid);

    return 0;
}

int ats_init_vqps(struct wpt *wpt)
{
    int nr_vqps = MAX_VQPS; //get_nr_vqps(wpt);
    struct ats *ats = wpt->ats;
    int i;

    ats_info("nr_vqps=%d\n", nr_vqps);
    ats->nr_vqps = nr_vqps;
    ats->vqps = kmalloc(sizeof(struct nvme_qpair) * nr_vqps, GFP_KERNEL);
    if (!ats->vqps) {
        return -ENOMEM;
    }

    for (i = 0; i < nr_vqps; i++) {
        struct nvme_qpair *vqp = &ats->vqps[i];
        memset(vqp, 0, sizeof(*vqp));
        ats_init_vqp(wpt, vqp, i + 1);
    }

    return 0;
}

void ats_free_vqps(struct wpt *wpt)
{
    int nr_vqps = MAX_VQPS;
    struct ats *ats = wpt->ats;
    int i;

    for (i = 0; i < nr_vqps; i++) {
        struct nvme_qpair *vqp = &ats->vqps[i];
        /* Coperd: unmap vSQ */
        if (vqp->sq_cmds) {
            vunmap((void *)vqp->sq_cmds);
        }
        /* Coperd: unmap vCQ */
        if (vqp->cqes) {
            vunmap((void *)vqp->cqes);
        }

        /* Coperd: release reference to virq-eventfd */
        if (vqp->guest_notifier_ctx) {
            eventfd_ctx_put(vqp->guest_notifier_ctx);
        }
        if (vqp->guest_notifier_filp) {
            fput(vqp->guest_notifier_filp);
        }
    }

    kfree(ats->vqps);
}

#ifdef MULTI_QP_PER_VHD
/* Assumes multiple vQPs and one VM - below is the old version */
struct nvme_qpair *ats_get_vqp(struct wpt *wpt, struct wpt_qp *qp)
{
    struct ats *ats = wpt->ats;
    struct wpt_qp_data *qdata = qp->data;
    struct nvme_qpair *vqp;
    int qid = -1;
    int i;

    printk("Number of ndbvms = %d\n", wpt->ndbvms);
    printk("This VM's PID = %d\n", qdata->vm_pid);
    printk("This VM's QID = %d\n", qdata->q_id);

    if (qdata->q_id == 0) {
	    printk("passed QID = 0; returning first vQP\n");
	    return &ats->vqps[0];
    }

    for (i = 0; i < wpt->ndbvms; i++) {
        printk("This DBVM's PID (local WPT) = %d\n", wpt->dbvms[i].pid);
        if ((qdata->vm_pid == wpt->dbvms[i].pid) && (qdata->q_id == wpt->dbvms[i].qid)) {
            printk("VM's PID and DBVM's PID equal, same for QP IDs\n");
            printk("QID of this QP = %d\n", wpt->dbvms[i].qid);
            qid = wpt->dbvms[i].qid;
            break;
        }
    }

    /* Coperd: die early */
    if (i == wpt->ndbvms) {
        BUG();
    }

    BUG_ON(qid < 0 || qid >= MAX_VQPS);

    /* Coperd: qid starts from 1 */
    vqp = &ats->vqps[qid - 1];
    printk("Coperd,%s,vqp-id:%d\n", __func__, qid);

    return vqp;
}

#else

struct nvme_qpair *ats_get_vqp(struct wpt *wpt, struct wpt_qp *qp)
{
	struct ats *ats = wpt->ats;
	struct wpt_qp_data *qdata = qp->data;
	struct nvme_qpair *vqp;
	int qid = -1;
	int i;

	for (i = 0; i < wpt->ndbvms; i++) {
		if (qdata->vm_pid == wpt->dbvms[i].pid) {
			qid = wpt->dbvms[i].qid;
			break;
		}
	}

	/* Coperd: die early */
	if (i == wpt->ndbvms) {
		BUG();
	}

	BUG_ON(qid < 0 || qid >= MAX_VQPS);

	/* Coperd: qid starts from 1 */
	vqp = &ats->vqps[qid - 1];
	printk("Coperd,%s,vqp-id:%d\n", __func__, qid);

	return vqp;
}
#endif

static const char *get_qt_str(int qt)
{
    switch (qt) {
    case WPT_SQ_T:
        return "SQ";
    case WPT_CQ_T:
        return "CQ";
    case WPT_DB_T:
        return "DB";
    default:
        return "ErrQT";
    }
}

void ats_update_vqp_state(struct nvme_qpair *vqp, int qt)
{
    //unsigned long flags;

    BUG_ON(vqp->is_active);

    vqp->nr_ready_res++;
    ats_info("Reg vQP[%d].%s,nr_ready_res=%d\n", vqp->qid, get_qt_str(qt),
            vqp->nr_ready_res);

    /* Coperd: SPDK quirks: use DB page for multiple iterations of vQP */
    if (vqp->nr_ready_res == 1 && qt == WPT_DB_T) {
        vqp->spdk_quirk = true;
    }

    if (vqp->spdk_quirk && vqp->nr_ready_res == 2 && qt == WPT_SQ_T) {
        /* Coperd: mark vQP as ready anyway */
        vqp->nr_ready_res = 3;
        ats_info("Quirk-vQP[%d].nr_ready_res=%d\n", vqp->qid, vqp->nr_ready_res);
    }

    if (vqp->nr_ready_res == 3) {
        /* Coperd: vqp is ready to poll from SoC */
        set_sp(vqp->sp_db);
        //write_lock_irqsave(&vqp->q_rwlock, flags);
        vqp->is_active = true;
        //write_unlock_irqrestore(&vqp->q_rwlock, flags);
    } else if (vqp->nr_ready_res >= 4 || vqp->nr_ready_res <= 0) {
        BUG();
    }
}

int ats_map_vsq(struct wpt *wpt, struct wpt_qp *qp)
{
    struct wpt_qp_data *qdata = qp->data;
    struct nvme_qpair *vqp = ats_get_vqp(wpt, qp);
    int n = get_q_npages(qdata);
    pgprot_t prot = PAGE_KERNEL_NOCACHE;
    int i;

    for (i = 0; i < n; i++) {
        vqp->vsq_pgs[i] = pfn_to_page(qdata->q_baddr[i]);
    }

    BUG_ON(vqp->is_active);
    BUG_ON(*(vqp->sp_db) != 0);
    //WARN_ON(vqp->qid != qdata->q_id);
    if (vqp->sq_db) {
        WARN_ON(*(vqp->sq_db));
    }
    if (vqp->sq_cmds) {
        WARN_ON(1);
        vunmap((void *)vqp->sq_cmds);
        vqp->sq_cmds = NULL;
    }
    vqp->sq_cmds = vmap(vqp->vsq_pgs, n, VM_MAP | VM_IOREMAP, prot);
    if (!vqp->sq_cmds) {
        return -EINVAL;
    }

    /* Coperd: when processing vCQ reg, q_depth must have been filled */
    WARN_ON(qdata->q_nr_entry != vqp->q_depth);
    WARN_ON(qdata->vm_pid != vqp->vm_pid);

    ats_update_vqp_state(vqp, qdata->q_type);

    return 0;
}

int ats_map_vcq(struct wpt *wpt, struct wpt_qp *qp)
{
    struct wpt_qp_data *qdata = qp->data;
    struct nvme_qpair *vqp = ats_get_vqp(wpt, qp);
    int n = get_q_npages(qdata);
    pgprot_t prot = PAGE_KERNEL_NOCACHE;
    int i;

    BUG_ON(vqp->is_active);
    BUG_ON(*(vqp->sp_db) != 0);
    //WARN_ON(vqp->qid != qdata->q_id);
    if (vqp->cq_db) {
        WARN_ON(*(vqp->cq_db));
    }
    for (i = 0; i < n; i++) {
        vqp->vcq_pgs[i] = pfn_to_page(qdata->q_baddr[i]);
    }
    if (vqp->cqes) {
        WARN_ON(1);
        vunmap((void *)vqp->cqes);
        vqp->cqes = NULL;
    }
    vqp->cqes = vmap(vqp->vcq_pgs, n, VM_MAP | VM_IOREMAP, prot);
    if (!vqp->cqes) {
        return -EINVAL;
    }
    /* Coperd: now we have the chance to set real info */
    vqp->q_depth = qdata->q_nr_entry;
    ats_info("vQP[%d].depth=%d\n", vqp->qid, vqp->q_depth);
    vqp->vm_pid = qdata->vm_pid;

    ats_update_vqp_state(vqp, qdata->q_type);

    return 0;
}

/* Coperd: setup irqfd for virtual interrupt injection */
int ats_setup_virq(struct wpt *wpt, struct wpt_qp *qp)
{
    struct nvme_qpair *vqp = ats_get_vqp(wpt, qp);
    int efd = qp->data->guest_notifier_fd;
    struct eventfd_ctx *ctx = NULL;
    struct file *eventfp, *filp = NULL;

    eventfp = (efd == -1) ? NULL : eventfd_fget(efd);
    if (IS_ERR(eventfp)) {
        return PTR_ERR(eventfp);
    }

    if (eventfp != vqp->guest_notifier_filp) {
        filp = vqp->guest_notifier_filp;
        ctx = vqp->guest_notifier_ctx;
        vqp->guest_notifier_filp = eventfp;
        vqp->guest_notifier_ctx = eventfp ? eventfd_ctx_fileget(eventfp) : NULL;
        printk("====> Setup virq for vCQ[%d],eventfp=%lx,ctx=%lx\n", vqp->qid,
                (unsigned long)eventfp, (unsigned long)vqp->guest_notifier_ctx);
    } else {
        filp = eventfp;
    }

    if (ctx) {
        eventfd_ctx_put(ctx);
    }
    if (filp) {
        fput(filp);
    }

    return 0;
}

int ats_map_vqp(struct wpt *wpt, struct wpt_qp *qp)
{
    int qt = qp->data->q_type;

    switch (qt) {
    case WPT_SQ_T:
        return ats_map_vsq(wpt, qp);
    case WPT_CQ_T:
        return ats_map_vcq(wpt, qp);
    default:
        ats_err("ERROR,mapping unknown vQP type\n");
        return -1;
    }
}

#ifdef MULTI_QP_PER_VHD
int ats_map_vqp_db(struct wpt *wpt, struct wpt_qp *qp)
{
    int i, ret;
    int ats_qid;
    int qidx, qidx_soc;
    int stride = 1;

    struct nvme_qpair *vqp;
    struct ats *ats = wpt->ats;
    struct wpt_qp_data *qdata = qp->data;

    /* Doorbell base address */
    unsigned long dbpfn = qp->data->q_baddr[0];

    /* When mapping DBs, QID should be equal to 0 */
    BUG_ON(qdata->q_id != 0);

    /* Map the doorbell memory into the VM */
    ret = ats_reinit_dbbuf(wpt, dbpfn, 1);
    if (ret) {
        return ret;
    }

    for (i = 0; i < wpt->ndbvms; i++) {
        vqp = &ats->vqps[i];
        ats_qid = vqp->qid;

        printk("Mapping dbells for vQP with ID %d\n", ats_qid);

        /* Shouldn't have dbells mapped already */
        BUG_ON(*(vqp->sp_db) != 0);

        /* Compute offsets */
        qidx = sq_idx(vqp->qid, stride);
        qidx_soc = sq_idx_soc(vqp->qid, stride);

        /* Map SQ/CQ doorbells */
        vqp->sq_db = &(ats->dbbuf[0][qidx]);
        vqp->cq_db = vqp->sq_db + 1;
        vqp->sq_db_soc = &(ats->dbbuf[0][qidx_soc]);

        ats_update_vqp_state(vqp, qp->data->q_type);
    }

    return 0;
}

#else

int ats_map_vqp_db(struct wpt *wpt, struct wpt_qp *qp)
{
    struct ats *ats = wpt->ats;
    struct nvme_qpair *vqp = ats_get_vqp(wpt, qp);
    int ats_qid = vqp->qid;
    int qidx, qidx_soc;
    int stride = 1;
    unsigned long dbpfn = qp->data->q_baddr[0];
    int ret;

    printk("[stnovako] mapping DB buffer\n");
    ret = ats_reinit_dbbuf(wpt, dbpfn, ats_qid);
    if (ret) {
        return ret;
    }

    /* Coperd: only update vqp info for the corresponding DBVM */
    BUG_ON(*(vqp->sp_db) != 0);
    /* Coperd: TODO: 1 vQP for each DBVM, thus sqidx is 1 within dbbuf */
    qidx = sq_idx(1/*vqp->qid*/, stride);
    qidx_soc = sq_idx_soc(1/*vqp->qid*/, stride);
    vqp->sq_db = &(ats->dbbuf[ats_qid - 1][qidx]);
    vqp->cq_db = vqp->sq_db + 1;
    vqp->sq_db_soc = &(ats->dbbuf[ats_qid - 1][qidx_soc]);

    ats_update_vqp_state(vqp, qp->data->q_type);

    return 0;
}
#endif

int ats_init_ats(struct wpt *wpt)
{
    int ret;

    wpt->ats = kmalloc(sizeof(struct ats), GFP_KERNEL);
    if (!wpt->ats) {
        return -ENOMEM;
    }
    memset(wpt->ats, 0, sizeof(*wpt->ats));
    wpt->ats->wpt = wpt;

    ret = ats_init_vqps(wpt);
    if (ret) {
        goto err;
    }

    return 0;

err:
    ats_free_vqps(wpt);
    return ret;
}

void ats_free_ats(struct wpt *wpt)
{
    ats_free_vqps(wpt);
    kfree(wpt->ats);
}

/* Coperd: ATS polling thread */
int ats_init_poller(struct wpt *wpt)
{
    struct ats *ats = wpt->ats;

    /* Coperd: kick start the polling thread */
    ats->ats_ts = kthread_create(ats_ts, wpt, "ATS-poller");
    if (IS_ERR(ats->ats_ts)) {
        int err = PTR_ERR(ats->ats_ts);
        ats_err("Cound not allocate ats thread (%d)\n", err);
        return err;
    }

    kthread_bind(ats->ats_ts, pin_to);
    wake_up_process(ats->ats_ts);
    ats_info("wpt-ats-polling thread created\n");

    return 0;
}

void ats_stop_poller(struct wpt *wpt)
{
    if (wpt->ats->ats_ts)
        kthread_stop(wpt->ats->ats_ts);
}
