#include <linux/module.h>
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

#include "wpt.h"

#define MAX_NR_PQPS  (64)

#ifndef NVM_OP_PREAD
#define NVM_OP_PREAD    0x92
#endif
#ifndef NVM_IO_SUSPEND
#define NVM_IO_SUSPEND  0x80
#endif
#ifndef NVM_IO_SCRAMBLE_ENABLE
#define NVM_IO_SCRAMBLE_ENABLE 0x200
#endif

static bool oc_mode = true;

static struct nvme_qpair pqps[MAX_NR_PQPS];
static struct task_struct *oct_ts;

static uint64_t gpg = 0;
static uint64_t gblk = 0;

//static struct timer_list octimer;

uint64_t leap_addr_lba2dev(uint64_t spba)
{
    /* Coperd: for OCSSD w/ Toshiba 4-plane NAND */
    /* Coperd: TODO: support OCSSD w/ Micron 2-plane NAND */
    uint8_t ch_off = 26; // micron: 25
    uint8_t lun_off = 23; // micron: 22
    uint8_t pl_off = 2;
    uint8_t blk_off = 12;
    uint8_t pg_off = 4; // micron: 3
    uint8_t sec_off = 0;

    uint64_t addr = 0;

    uint64_t pg = gpg;
    uint64_t blk;

    gpg++;
    if (gpg == 255) {
        gpg = 0;
        gblk++;
    }
    blk = gblk;

    addr |= 0 << ch_off;    // chnl
    addr |= 0 << lun_off; // lun
    addr |= 0 << pl_off;    // pl
    addr |= blk << blk_off;   // blk
    addr |= pg << pg_off;   // pg
    addr |= 0 << sec_off; // sec

    return addr;
}

static struct nvme_qpair *oct_init_nvme_qpair(int qid)
{
    struct nvme_qpair *pqp = &pqps[qid];

    print_nvmeq(&qpbuf[qid]);

    spin_lock_init(&pqp->q_lock);

    spin_lock_irq(&pqp->q_lock);
    pqp->sq_cmds = phys_to_virt(qpbuf[qid].sq_paddr);
    pqp->cqes = phys_to_virt(qpbuf[qid].cq_paddr);
    pqp->sq_db = ioremap(qpbuf[qid].db_paddr, 4);
    //writel(10, pqp->sq_db);
    //*(pqp->sq_db) = 1;
    //printk("Coperd,%s,sq_db=%p, tail=%d\n", __func__, pqp->sq_db, *(pqp->sq_db));
    pqp->cq_db = ioremap(qpbuf[qid].db_paddr + 4, 4);
    //printk("Coperd,%s,cq_db=%p\n", __func__, pqp->cq_db);

    pqp->sq_tail = 0;
    pqp->cq_head = 0;
    pqp->cq_phase = 1;
    pqp->q_depth = qpbuf[qid].q_depth;
    spin_unlock_irq(&pqp->q_lock);

    return pqp;
}

static void oct_compose_nvme_cmd(struct nvme_command *cmd, void *buf_addr)
{
    struct nvme_cmd *c = &(cmd->c);

    BUG_ON(sizeof(*cmd) != 64);
    memset(c, 0, sizeof(*c));

    c->opcode = 0x2;
    //c.flags = NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE;
    c->cid = 8;
    c->nsid = cpu_to_le32(1); // is it zero??
    c->metadata = cpu_to_le64(0); // rqd->dma_meta_list
    c->prp1 = cpu_to_le64(virt_to_phys(buf_addr)); // virt_to_phys(buf)
    //c.prp2 = XXX;
    c->spba = cpu_to_le64(0); // chnl:1, others 0
    c->length = cpu_to_le16(0); // rqd->nr_ppas - 1
    //c->control = cpu_to_le16(NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE); // rqd->flags
    //c.dsmgmt = xx;
}

static void oct_compose_oc_cmd(struct nvme_command *cmd, void *buf_addr)
{
    struct nvme_cmd *c = &(cmd->c);

    BUG_ON(sizeof(*cmd) != 64);
    memset(c, 0, sizeof(*c));

    c->opcode = NVM_OP_PREAD;
    //c.flags = NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE;
    c->cid = 8;
    c->nsid = cpu_to_le32(1); // is it zero??
    c->metadata = cpu_to_le64(0); // rqd->dma_meta_list
    c->prp1 = cpu_to_le64(virt_to_phys(buf_addr)); // virt_to_phys(buf)
    //c.prp2 = XXX;
    c->spba = cpu_to_le64(leap_addr_lba2dev(0)); // chnl:1, others 0
    c->length = cpu_to_le16(0); // rqd->nr_ppas - 1
    c->control = cpu_to_le16(NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE); // rqd->flags
    //c.dsmgmt = xx;
}

static void oct_do_test(void)
{
    int i = 0;
    struct nvme_qpair *pqp;
    struct nvme_command *cmd;
    void *buf;
    int r;
    ktime_t st, et;
    void (*oct_compose_cmd_fn)(struct nvme_command *cmd, void *buf_addr);

    buf = kzalloc(4096, GFP_KERNEL);
    if (!buf) {
        printk("Coperd,buf allocation failed\n");
        return;
    }

    cmd = kmalloc(sizeof(*cmd), GFP_KERNEL);
    if (!cmd) {
        printk("Coperd,cmd allocation failed\n");
        goto err_kmalloc_cmd;
    }

    pqp = oct_init_nvme_qpair(13);

    if (oc_mode) {
        oct_compose_cmd_fn = &oct_compose_oc_cmd;
    } else {
        oct_compose_cmd_fn = &oct_compose_nvme_cmd;
    }

    for (i = 0; i < 1000; i++) {
        (*oct_compose_cmd_fn)(cmd, buf);
        spin_lock_irq(&pqp->q_lock);
        nvme_submit_cmd(pqp, cmd);
        spin_unlock_irq(&pqp->q_lock);
        st = ktime_get();
        while (1) {
            r = nvme_poll(pqp);
            if (r)
                break;
        }
        et = ktime_get();
        printk("Coperd,IO[%d],lat,%lld\n", i, ktime_us_delta(et, st));
        usleep_range(64, 128);
    }

    iounmap(pqp->sq_db);
    iounmap(pqp->cq_db);

    kfree(buf);
    kfree(cmd);

    return;

err_kmalloc_cmd:
    kfree(buf);
}

int oct_ts_func(void *data)
{
    oct_do_test();

    return 0;
}

int oct_thread_init(void)
{
    oct_ts = kthread_create(oct_ts_func, NULL, "OCT-thread");
    if (IS_ERR(oct_ts)) {
        int err = PTR_ERR(oct_ts);
        if (err != -EINTR) {
            pr_err("OCT: could not allocate oct thread (%d)\n", err);
            return 1;
        }
    }

    kthread_bind(oct_ts, 1);
    wake_up_process(oct_ts);
    printk("OCT thread created ..\n");

    return 0;
}

static int __init oct_module_init(void)
{
    //struct nvme_qpair *pqp;
    //timer_setup(&octimer, oct_do_test, 0);
    //mod_timer(&octimer, jiffies + msecs_to_jiffies(2000));
    //pqp = oct_init_nvme_qpair(9);

    oct_thread_init();

    printk("Coperd,oct module loaded\n");

    return 0;
}

static void oct_module_exit(void)
{
    //del_timer(&octimer);

    printk("Coperd,unregistered oct char dev\n");
}

module_init(oct_module_init);
module_exit(oct_module_exit);

MODULE_AUTHOR("Huaicheng Li <huaicheng@cs.uchicago.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("driver for OCSSD direct accessing");
MODULE_VERSION("0.1");
