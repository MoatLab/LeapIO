#ifndef __WPT_H
#define __WPT_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/smp.h>

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/lightnvm.h>
#include <linux/kvm.h>
#include <linux/kvm_types.h>
#include <asm/kvm_host.h>
#include <linux/kvm_host.h>
#include <linux/proc_fs.h>

#include "rdma.h"

#undef ATS_DEBUG
//#define ATS_DEBUG

#define ats_info(fmt, args...) printk("ATS,%s: " fmt, __func__, ## args)
#define ats_err(fmt, args...) pr_err("ATS-ERR,%s,%d:" fmt, __func__, __LINE__, ## args)

#ifdef ATS_DEBUG
#define ats_debug(fmt, args...) printk("ATS,%s: " fmt, __func__, ## args)
#else
#define ats_debug(fmt, args...)
#endif

#define NVME_CMD_SZ (64)
#define NVME_CPL_SZ (16)


/* Coperd: simply walk page table */
#define WPT_CMD_DUMP    10
/* Coperd: register SQ/CQ buffer */
#define WPT_CMD_REG     11
/* Coperd: map SQ/CQ buffer to user space */
#define WPT_CMD_MAP     12
/* Coperd: swap two user pages for testing */

#define WPT_CMD_UNMAP   13
#define WPT_CMD_SWAP    14
#define WPT_CMD_MAP_PDB 15
#define WPT_CMD_ATS     16
#define WPT_CMD_UNREG   17
#define WPT_CMD_GET_PDB 18

#define WPT_CMD_ADMIN_PASSTHRU_GETBBTBL 19
#define WPT_CMD_ADMIN_PASSTHRU_IDENTITY 20

#define WPT_MAJOR       200
#define WPT_MAX_MINORS  5

/* Coperd: represent queue type */
#define WPT_Q_NPAGES    16
#define WPT_Q_T_NUM     2

#define WPT_DB_T        (-1)
#define WPT_SQ_T        (0)
#define WPT_CQ_T        (1)

#define NVME_SQE_SZ     (64)
#define NVME_CQE_SZ     (16)

#define NVME_CMD_FLUSH  0x0
#define NVME_CMD_WRITE  0x1
#define NVME_CMD_READ   0x2


/* Coperd: 4096 / 64 = 64 */
#define NR_CMDS_PER_PG  (64)

#define WPT_INVALID_PFN (~0ULL)

#define MAX_VQPS    (16)

struct wpt_dev {
    spinlock_t lock;
    int users;
};

struct wpt_dev_data {
    struct cdev cdev;

    /* more here */
};

/*
 * Coperd: struct holding SQ/CQ buffer info
 * Use physical base addr for now, must be continuous buffer
 */
struct wpt_qp_data {
    unsigned long q_baddr[WPT_Q_NPAGES];
    int q_entry_sz;
    int q_nr_entry;
    int q_id;
    int q_type;

    pid_t vm_pid;
    int guest_notifier_fd;
};

struct wpt_qp {
    struct wpt_qp_data *data;
    struct list_head list;
    /* Coperd: used for restoring map-caller's original memory mapping */
    unsigned long mapper_va[WPT_Q_NPAGES];
    unsigned long mapper_pfn[WPT_Q_NPAGES];
    int nvqs;
    bool mapped;
};

/* Coperd: manage queue pair metadata */
struct wpt_qpair_meta {
    struct list_head tomap_db;
    struct list_head mapped_db;
    struct list_head tomap[WPT_Q_T_NUM];
    struct list_head mapped[WPT_Q_T_NUM];
};

struct dbvm {
    pid_t pid;
    /* Coperd: for now, each DBVM is assigned only one vQP */
    int qid;
    /* more info later */
};

struct wpt {
    struct wpt_dev *wpt_dev;
    struct wpt_dev_data wpt_dev_data[WPT_MAX_MINORS];
    struct wpt_qpair_meta *qpair_meta;
    struct ats *ats;

    struct mm_struct *soc_mm;
    unsigned long soc_va;
    struct vm_area_struct *soc_vma;

    struct page *sppage;
    u8 *spbuf; /* first half page in sppage */
    u32 *sibuf; /* second half page in sppage */
    u64 sppfn;

    void *admin_q; /* Coperd: admin request queue structure for admin cmd */
    int data_shift;
    int mdts;
    int leap_nr_pqps;

    /* Coperd: record all the info of registered DBVMs */
    struct dbvm dbvms[16];
    int ndbvms;

    void *dmabuf;
    u64 dmabuf_phys;

    struct rctx rctxs[16];
};

struct ats_data {
    pid_t pid;
    unsigned long addr;
};

struct nvme_cmd {
    u8 opcode;
    u8 flags;
    u16 cid;
    u32 nsid;
    u64 rsvd2;
    u64 metadata;
    u64 prp1;
    u64 prp2;
    u64 spba;
    u16 length;
    u16 control;
    u32 dsmgmt;
    u64 resv;
};

struct nvme_completion {
    union nvme_result {
        u32 u16;
        u32 u32;
        u64 u64;
    } result;
    u16 sq_head;
    u16 sq_id;
    u16 cid;
    u16 status;
};

/*
 * Coperd: for LeapIO
 * TODO: be extremely careful about this structure, must be sync'ed with the one
 * from host NVMe driver
 */
struct leap_qpbuf {
    int qid;
    int q_depth;
    u64 sq_paddr;	/* SQ physical address */
    u64 cq_paddr;	/* CQ physical address */
    u64 db_paddr;	/* Doorbell physical address */
    int stride;
    int lba_shift;
    int mdts;
    int nr_io_queues_leap;
};

extern struct leap_qpbuf qpbuf[64];
extern struct leap_qpbuf *qpbufp;
extern struct request_queue *admin_qp;


struct ats {
    struct wpt *wpt;

    int nr_vqps;
    u32 *dbbuf[16]; /* Coperd: one for each vNVMe device */
    struct page *dbpg[16];
    struct nvme_qpair *vqps;
    /* Coperd: the thread can only start polling after this is set */
    bool res_reg_done;
    struct task_struct *ats_ts;
    struct timer_list ats_timer;
};

struct nvme_sgl_desc {
    u64 addr;
    u32 length;
    u8 rsvd[3];
    u8 type;
};

struct nvme_keyed_sgl_desc {
    u64 addr;
    u8 length[3];
    u8 key[4];
    u8 type;
};

union nvme_data_ptr {
    struct {
        u64 prp1;
        u64 prp2;
    } prp;
    struct nvme_sgl_desc sgl;
    struct nvme_keyed_sgl_desc ksgl;
};

struct nvme_common_cmd {
    u8 opcode;
    u8 flags;
    u16 command_id;
    u32 nsid;
    u32 cdw2[2];
    u64 metadata;
    union nvme_data_ptr dptr;
    u32 cdw10[6];
};

struct nvme_rw_cmd {
    u8 opcode;
    u8 flags;
    u16 cid;
    u32 nsid;
    u64 rsvd2;
    u64 metadata;
    union nvme_data_ptr dptr;
    u64 slba;
    u16 nlb;
    u16 control;
    u32 dsmgmt;
    u32 reftag;
    u16 apptag;
    u16 appmask;
};

/* Coperd: OCSSD command format for read/write/erase */
struct nvme_ocrw_cmd {
    u8 opcode;
    u8 flags;
    u16 cid;
    u32 nsid;
    u64 rsvd2;
    u64 metadata;
    u64 prp1;
    u64 prp2;
    u64 spba;
    u16 nlb;
    u16 control;
    u32 dsmgmt;
    u64 resv;
};

struct nvme_command {
    union {
        struct nvme_common_cmd common;
        struct nvme_rw_cmd rw;
        struct nvme_ocrw_cmd ocrw;
        struct nvme_cmd c;
    };
};

struct wpt_admin_passthru_data {
    struct nvme_command c;
    pid_t vm_pid;
    void *buf;
};

struct nvme_nvm_getbbtbl {
    u8 opcode;
    u8 flags;
    u16 command_id;
    u32 nsid;
    u64	rsvd[2];
    u64 prp1;
    u64 prp2;
    u64 spba;
    u32 rsvd4[4];
};

struct nvme_nvm_setbbtbl {
    u8 opcode;
    u8 flags;
    u16 command_id;
    u32 nsid;
    u64 rsvd[2];
    u64 prp1;
    u64 prp2;
    u64 spba;
    u16 nlb;
    u8 value;
    u8 rsvd3;
    u32 rsvd4[3];
};

struct nvme_nvm_identity {
    u8 opcode;
    u8 flags;
    u16 cid;
    u32 nsid;
    u64 rsvd[2];
    u64 prp1;
    u64 prp2;
    u32 chnl_off;
    u32 rsvd11[5];
};

struct nvme_nvm_command {
    union {
        struct nvme_nvm_identity identity;
        struct nvme_nvm_getbbtbl get_bb;
        struct nvme_nvm_setbbtbl set_bb;
    };
};

struct nvme_nvm_bb_tbl {
    u8 tblid[4];
    u16 verid;
    u16 revid;
    u32 rvsd1;
    u32 tblks;
    u32 tfact;
    u32 tgrown;
    u32 tdresv;
    u32 thresv;
    u32 rsvd2[8];
    u8 blk[0];
};

enum ocssd_admin_opcode {
    ocadmin_identity = 0xe2,
    ocadmin_get_bbtbl = 0xf2,
    ocadmin_set_bbtbl = 0xf1,
};

struct nvme_qpair {
    spinlock_t q_lock;
    rwlock_t q_rwlock;
    volatile struct nvme_command *sq_cmds;
    volatile struct nvme_completion *cqes;
    volatile u32 *sq_db;
    volatile u32 *cq_db;
    volatile u32 *sq_db_soc; /* Coperd: DB for SoC */
    volatile u8 *sp_db; /* Coperd: "should-poll" doorbell */
    volatile u32 *si_db; /* Coperd: "should-interrupt" doorbell */
    u16 q_depth;
    u16 sq_tail;
    u16 cq_head;
    u16 qid;
    u8 cq_phase;

    /*
     * Coperd: divide each vsq into multiple page-sized small buffers
     * each page contains 64 NVMe commands
     */
    u16 cq_tail;
    u16 sq_head;
    struct page *vsq_pgs[WPT_Q_NPAGES];
    struct page *vcq_pgs[4];

    pid_t vm_pid;
    u8 nr_ready_res;
    bool should_do_fake_cqe;
    bool is_active;
    bool spdk_quirk;

    u32 prev_si; /* Coperd: should-interrupt doorbell value when read last time
                  * we compare prev_si with current si_db value to decide
                  * if a new virtual interrupt is needed for the VM
                  */
    struct file *guest_notifier_filp;
    struct eventfd_ctx *guest_notifier_ctx;

    struct kvm *kvm;

    struct rctx *rctx;
};

/* Coperd: wpt wrapper of nvme_qpair */
struct wpt_qpair {
    struct nvme_qpair *qpair;
    pid_t vm_pid;
    int wpt_vmid;
    int wpt_devid;
    int wpt_qid;
};

extern struct wpt *gwpt;

static inline struct wpt *WPT(void)
{
    BUG_ON(!gwpt);
    return gwpt;
}

/* Coperd: wpt-util */

void get_pgt_macro(void);
pte_t *va2pte(struct mm_struct *mm, unsigned long addr);
struct kvm *get_kvm(pid_t vm_pid);
int vaddr_get_pfn(struct mm_struct *mm, unsigned long vaddr, unsigned long *pfn);
int put_pfn(unsigned long pfn);
u64 hva2hpa(struct mm_struct *mm, unsigned long addr);

/* Coperd: end wpt-util */

/* Coperd: wpt-qp */
inline bool wpt_is_q_type_valid(struct wpt_qp_data *data);
inline bool wpt_is_q_sdb(struct wpt_qp_data *data);
int get_q_npages(struct wpt_qp_data *data);
int wpt_qpair_meta_init(struct wpt *wpt);
void wpt_qpair_meta_free(struct wpt_qpair_meta *qpair_meta);
void dump_wpt_qp_data(struct wpt_qp_data *data);

void print_nvmecmd(struct nvme_rw_cmd *c);
void print_completion(struct nvme_completion c);
void print_nvmeq(struct leap_qpbuf *buf);
struct leap_qpbuf *get_qpbuf(void);

void wpt_deinit(void);
/* Coperd: end wpt-qp */



/* Coperd: wpt-ats */

int wpt_do_cmd_ats(unsigned long arg);
int ats_init_poller(struct wpt *wpt);
int ats_init_ats(struct wpt *wpt);
void ats_free_ats(struct wpt *wpt);
void ats_free_vqps(struct wpt *wpt);
int ats_disable_vqp(struct ats *ats, struct wpt_qp *qp);
int ats_setup_virq(struct wpt *wpt, struct wpt_qp *qp);
void ats_stop_poller(struct wpt *wpt);
inline u64 ats_do_ats_one_addr(struct kvm *kvm, u64 gpa);
struct nvme_qpair *ats_get_vqp(struct wpt *wpt, struct wpt_qp *qp);

/* Coperd: end wpt-ats */
int ats_init_vqps(struct wpt *wpt);
int ats_map_vqp_db(struct wpt *wpt, struct wpt_qp *sdb_qp);
int ats_map_vqp_db_same_vm(struct wpt *wpt, struct wpt_qp *sdb_qp);
int ats_map_vqp(struct wpt *wpt, struct wpt_qp *qp);
extern bool res_reg_done;


/* Coperd: wpt-core */
extern unsigned int pin_to;

/* Coperd: pnvme.c */
bool nvme_sq_empty(struct nvme_qpair *qp);
void nvme_submit_cmd(struct nvme_qpair *qpair, struct nvme_command *cmd);
int nvme_poll(struct nvme_qpair *qpair);

void nvme_inc_sq_head(struct nvme_qpair *vqp);
void nvme_update_sq_tail(struct nvme_qpair *vqp);
void nvme_update_sq_tail_soc(struct nvme_qpair *vqp);
void nvme_inc_cq_tail(struct nvme_qpair *vqp);
void nvme_cq_update_head(struct nvme_qpair *vqp);
int nvme_cq_full(struct nvme_qpair *vqp);

int wpt_do_cmd_dump(unsigned long vaddr);
int wpt_do_cmd_swap(unsigned long vaddr);


extern unsigned int use_rdma_for_vqp;

extern int nvme_submit_sync_cmd(struct request_queue *q, struct nvme_command *c,
        void *buf, unsigned buflen);


#endif
