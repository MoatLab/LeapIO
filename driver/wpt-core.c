/*
 * File wpt-core.c
 *
 * LeapIO host driver main entry, WPT originally stands for
 * "walking-page-tables", but this driver's functionalities have gone far beyond
 * that.
 *
 * Communication to this interface is through a char device exposed to the user
 * space and mainly used by FEMU/QEMU - the VM hypervisor to setup relevant
 * information for the SoC
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include "wpt.h"
#include "globals.h"

/* Please MATCH the variable in SOCP */
int NR_DBVMS = 2;

//#define DEBUG

unsigned int pin_to = 7;
module_param(pin_to, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(pin_to, "pin ATS thread to certain core id");

unsigned int use_soc = 0;
module_param(use_soc, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(use_soc, "whether running QL with an actual SoC or not");

unsigned int client_mode_only = 0;
module_param(client_mode_only, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(pin_to, "run WPT only for socvm-client");

/* Coperd: for vQP routing via RDMA */
unsigned int use_rdma_for_vqp = 0;
module_param(use_rdma_for_vqp, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(use_rdma_for_vqp, "whether to use RDMA for vQP sharing");

unsigned int pport = 9999;
module_param(pport, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(pport, "Port to connect to");

struct wpt *gwpt;
static struct proc_dir_entry *wpt_proc;

static int wpt_dev_init(struct wpt *wpt)
{
    wpt->wpt_dev = kmalloc(sizeof(struct wpt_dev), GFP_KERNEL);
    if (!wpt->wpt_dev) {
        return -1;
    }

    spin_lock_init(&(wpt->wpt_dev->lock));
    wpt->wpt_dev->users = 0;

    return 0;
}

static void wpt_dev_free(struct wpt *wpt)
{
    if (wpt->wpt_dev) {
        kfree(wpt->wpt_dev);
    }
}

static int wpt_open(struct inode *inode, struct file *file)
{
    struct wpt *wpt = WPT();
    struct wpt_dev *dev = wpt->wpt_dev;
    struct wpt_dev_data *wpt_data;

    printk("Coperd,%s,start\n", __func__);
    wpt_data = container_of(inode->i_cdev, struct wpt_dev_data, cdev);

    file->private_data = wpt_data;

    spin_lock(&(dev->lock));
    dev->users++;
    spin_unlock(&(dev->lock));

    return 0;
}

static int wpt_release(struct inode *inode, struct file *filp)
{
    struct wpt *wpt = WPT();
    struct wpt_dev *dev = wpt->wpt_dev;

    spin_lock(&(dev->lock));
    dev->users--;
    spin_unlock(&(dev->lock));

    return 0;
}

static ssize_t wpt_read(struct file *filp, char __user *buf,
                        size_t count, loff_t *ppos)
{
    struct wpt_dev_data *wpt_data;

    wpt_data = (struct wpt_dev_data *)filp->private_data;

    return 0;
}

static ssize_t wpt_write(struct file *filp, const char __user *buf,
                        size_t count, loff_t *ppos)
{
    return 0;
}

static int wpt_mmap(struct file *filp, struct vm_area_struct *vma)
{
    return 0;
}

/* Coperd: check if addr maps to pfn by walking the page table again */
static int wpt_map_ok(struct wpt *wpt, unsigned long addr, u64 pfn)
{
    pte_t *ptep;
    u64 ppfn;

    ptep = va2pte(wpt->soc_mm, addr);
    ppfn = pte_pfn(*ptep);
    pte_unmap(ptep);

    if (ppfn != pfn) {
        return -1;
    }

    return 0;
}

static int wpt_remap_pfns(struct wpt *wpt, struct vm_area_struct *vma,
                         unsigned long va, unsigned long pfn, size_t size,
                         pgprot_t prot)
{
    int ret;

    if (use_soc) {
        printk_once("Coperd,%s,use_soc=1, doing nothing here..\n", __func__);
        return 0;
    }

    BUG_ON(!wpt);
    BUG_ON(!vma);
    //BUG_ON(!pfn_valid(pfn));

    ret = wpt_remap_pfn_range(vma, va, pfn, size, prot);
    if (ret) {
        return ret;
    }

    return wpt_map_ok(wpt, va, pfn);
}

/* Coperd: TODO: map physical DB BAR register */
static int wpt_map_pqp_db(unsigned long *addr)
{
    struct wpt *wpt = WPT();
    struct leap_qpbuf *qpbufp = get_qpbuf();
    int pqpid = num_present_cpus() + 1;
    struct leap_qpbuf *qpbuf = &qpbufp[pqpid];
    struct vm_area_struct *vma = wpt->soc_vma;

    int qid = qpbuf->qid;
    u64 db_paddr = qpbuf->db_paddr;
    int stride = qpbuf->stride;
    int idx = qid * 2 * stride;

    /* Coperd: calculate the base paddr of DB BAR REG */
    u64 db_base_paddr = db_paddr - idx * sizeof(u32);
    u64 dbpfn = db_base_paddr >> PAGE_SHIFT;

    BUG_ON(pqpid != qid);

#ifdef DEBUG
    printk("Coperd,%s,qid=%d,q_depth=%d,sq_paddr=%llx,cq_paddr=%llx,db_paddr=%llx"
            ",stride=%d\n", __func__, qpbuf->qid, qpbuf->q_depth, qpbuf->sq_paddr,
            qpbuf->cq_paddr, qpbuf->db_paddr, qpbuf->stride);
#endif

    if (wpt_remap_pfns(wpt, vma, *addr, dbpfn, PAGE_SIZE, vma->vm_page_prot)) {
        printk("Coperd,%s,map pqp-DB to SoC failed\n", __func__);
        return -1;
    }

    *addr += PAGE_SIZE;

    return 0;
}

/* Coperd: return pQP DB phy addr back to caller */
static int wpt_get_pqp_db(unsigned long p)
{
    struct leap_qpbuf *qpbufp = get_qpbuf();
    /* in NVMe driver, pQPs start with qid=2 */
    int pqpid = 2;
    struct leap_qpbuf *qpbuf = &qpbufp[pqpid];
    int qid = qpbuf->qid;
    u64 db_paddr = qpbuf->db_paddr;
    int stride = qpbuf->stride;
    int idx = qid * 2 * stride;
    u64 db_base_paddr;
    int ret;

    /* Coperd: calculate the base paddr of DB BAR REG */
    BUG_ON(pqpid != qid);
    db_base_paddr = db_paddr - idx * sizeof(u32);
    db_base_paddr &= PAGE_MASK;
    printk("Coperd,pQP DB=0x%llx\n", db_base_paddr);
    BUG_ON(offset_in_page(db_base_paddr));

    ret = copy_to_user((void __user *)p, &db_base_paddr, sizeof(unsigned long));
    if (ret) {
        return -1;
    }

    return 0;
}

/* Coperd: map one pQP, TODO: merge w/ vQP mngt API later */
static int wpt_map_psq(struct leap_qpbuf *qpbuf, unsigned long *addr)
{
    struct wpt *wpt = WPT();
    unsigned long psqsz = PAGE_ALIGN(qpbuf->q_depth * NVME_SQE_SZ);
    struct vm_area_struct *vma = wpt->soc_vma;
    u64 sq_bpfn;

    sq_bpfn = qpbuf->sq_paddr >> PAGE_SHIFT;
    /* Coperd: map pSQ */
    if (wpt_remap_pfns(wpt, vma, *addr, sq_bpfn, psqsz, vma->vm_page_prot)) {
        printk("Coperd,%s,map psq to SoC failed\n", __func__);
        return -1;
    }

    *addr += psqsz;

    return 0;
}

static int wpt_map_psqs(struct leap_qpbuf *qpbufp, unsigned long *addr)
{
    struct wpt *wpt = WPT();
    struct leap_qpbuf *qpbuf;
    int spqpid = 2;
    /* the first QL-pQP qid is 2 and we have in total leap_nr_pqps QL-pQPs */
    int epqpid = wpt->leap_nr_pqps + 1;
    int ret;
    int i;

    /* Coperd: TODO */
    for (i = spqpid; i <= epqpid; i++) {
        printk("Coperd,%s,map pSQ[%d]\n", __func__, i);
        qpbuf = &qpbufp[i];
        ret = wpt_map_psq(qpbuf, addr);
        if (ret) {
            goto err;
        }
    }

    return 0;

err:
    i--;
    for (; i >= spqpid; i--) {
        /* Coperd: undo the mapping */
        /* Coperd: TODO TODO */
    }
    return ret;
}

static int wpt_map_pcq(struct leap_qpbuf *qpbuf, unsigned long *addr)
{
    struct wpt *wpt = WPT();
    struct vm_area_struct *vma = wpt->soc_vma;
    unsigned long pcqsz = PAGE_ALIGN(qpbuf->q_depth * NVME_CQE_SZ);
    u64 cq_bpfn;

    cq_bpfn = qpbuf->cq_paddr >> PAGE_SHIFT;

    if (wpt_remap_pfns(wpt, vma, *addr, cq_bpfn, pcqsz, vma->vm_page_prot)) {
        printk("Coperd,%s,map pcq to SoC failed\n", __func__);
        return -1;
    }

    *addr += pcqsz;

    return 0;
}

static int wpt_map_pcqs(struct leap_qpbuf *qpbufp, unsigned long *addr)
{
    struct wpt *wpt = WPT();
    struct leap_qpbuf *qpbuf;
    int spqpid = 2;
    int epqpid = wpt->leap_nr_pqps + 1;
    int ret;
    int i;

    /* Coperd: TODO */
    for (i = spqpid; i <= epqpid; i++) {
        printk("Coperd,%s,map pCQ[%d]\n", __func__, i);
        qpbuf = &qpbufp[i];
        ret = wpt_map_pcq(qpbuf, addr);
        if (ret) {
            goto err;
        }
    }

    return 0;

err:
    i--;
    for (; i >= spqpid; i--) {
        /* Coperd: undo the mapping */
        /* Coperd: TODO TODO */
    }
    return ret;
}

static int wpt_map_pqps(struct wpt *wpt, unsigned long vaddr)
{
    struct leap_qpbuf *qpbufp = get_qpbuf();
    unsigned long pdb_vaddr = vaddr + 8 * 1024 * 1024; /* Coperd: 8MB offset */
    unsigned long psq_vaddr, pcq_vaddr;
    int ret = 0;
#define NR_PQP  (8)

    /* Coperd: map pDB, one page is enough */
    //wpt_map_phy_db(&pdb_vaddr);
    //pqp_vaddr += PAGE_SIZE;

    /* pSQ starts at offset: 8MB+4KB */
    psq_vaddr = pdb_vaddr + PAGE_SIZE;
    ret = wpt_map_psqs(qpbufp, &psq_vaddr);
    if (ret) {
        goto err_map_psqs;
    }

    /* pCQ starts at offset: 12MB */
    pcq_vaddr = vaddr + 12 * 1024 * 1024;
    ret = wpt_map_pcqs(qpbufp, &pcq_vaddr);
    if (ret) {
        goto err_map_pcqs;
    }

    return 0;

err_map_psqs:
    printk("Coperd,%s,ERROR,map pCQs failed\n", __func__);
err_map_pcqs:
    /* Coperd: TODO TODO */
    printk("Coperd,%s,ERROR,map pSQs failed\n", __func__);

    return ret;
}

static unsigned long wpt_get_vqp_map_addr(struct wpt *wpt, struct wpt_qp *qp)
{
    int vqsz = qp->data->q_nr_entry * qp->data->q_entry_sz;
    struct nvme_qpair *vqp = ats_get_vqp(wpt, qp);
    int qid = vqp->qid;
    int qt = qp->data->q_type;
    size_t vsqsz;
    size_t vcqsz;
    /* Coperd: TODO: for now, support at most 16 DBVMs, each with 1 vQP */
    /* Coperd: default to vSQ base addr */
    unsigned long va = wpt->soc_va + PAGE_SIZE * MAX_VQPS;

    /* Coperd: suppose max vQD=1024 vQD (i.e., 16 pages for vSQ) */
    vsqsz = 16 * PAGE_SIZE;
    vcqsz = 4 * PAGE_SIZE;
    /* Coperd: TODO TODO */
    if (qt == WPT_CQ_T) {
        va += vsqsz * MAX_VQPS;
    }

    /* Coperd: offset according to <qid> TODO (vmid, devid, qid) */
    va += (qid - 1) * vqsz;

    return va;
}

/* Coperd: update SoC vaddr to map to the new vQP info */
/* Coperd: input already contains the latest info (b_addr) of the vQP */
static int wpt_map_vqp(struct wpt *wpt, struct wpt_qp *qp)
{
    struct vm_area_struct *vma = wpt->soc_vma;
    unsigned long pfn;
    int npages = get_q_npages(qp->data);
    unsigned long va = wpt_get_vqp_map_addr(wpt, qp);
    int ret;
    int i;

    /* Coperd: vQP pfns may not be continuous */
    for (i = 0; i < npages; i++) {
        pfn = qp->data->q_baddr[i];
        ret = wpt_remap_pfns(wpt, vma, va, pfn, PAGE_SIZE, vma->vm_page_prot);
        if (ret) {
            printk("Coperd,%s,ERROR,wpt_remap_pfns failed\n", __func__);
            goto err;
        }
        va += PAGE_SIZE;
    }

    return 0;

err:
    printk("Coperd,%s,ERROR,remap pfn failed\n", __func__);
    i--;
    while (i >= 0) {
        /* Coperd: restore orignal mapping */
        i--;
    }
    return ret;
}

static int wpt_map_vqp_db(struct wpt *wpt, struct wpt_qp *qp)
{
    struct vm_area_struct *vma = wpt->soc_vma;
    struct nvme_qpair *vqp = ats_get_vqp(wpt, qp);
    int ats_qid = vqp->qid;
    /* Coperd: calculate the DBBUF page offset */
    unsigned long va = wpt->soc_va + PAGE_SIZE * (ats_qid - 1);
    unsigned long pfn = qp->data->q_baddr[0];

    /* Coperd: only one page for Shadow DB */
    return wpt_remap_pfns(wpt, vma, va, pfn, PAGE_SIZE, vma->vm_page_prot);
}

static int wpt_do_cmd_reg_db(struct wpt *wpt, struct wpt_qp *qp)
{
    int ret;

    printk("Coperd,===> (1). Register vQP DB\n");

    ret = wpt_map_vqp_db(wpt, qp);
    if (ret) {
        goto err_map_vqp_db;
    }

    /* Coperd: update ATS nvmeq state */
    return ats_map_vqp_db(wpt, qp);

err_map_vqp_db:
    /* Coperd: restore prev mapping ? TODO TODO */
    return ret;
}

static int wpt_do_cmd_reg_vqp(struct wpt *wpt, struct wpt_qp *qp)
{
    int qt = qp->data->q_type;
    struct nvme_qpair *vqp = ats_get_vqp(wpt, qp);
    int ats_qid = vqp->qid;
    int p = (qt == WPT_SQ_T) ? 3 : 2;
    const char *s = (qt == WPT_SQ_T) ? "SQ" : "CQ";
    int ret;

    BUG_ON(qt != WPT_SQ_T && qt != WPT_CQ_T);
    printk("===> (%d). Register %s[%d]\n", p, s, ats_qid);

    vqp->kvm = get_kvm(qp->data->vm_pid);
    BUG_ON(!vqp->kvm);

    ret = wpt_map_vqp(wpt, qp);
    if (ret) {
        return ret;
    }

    /* Coperd: register irqfd info first */
    if (qt == WPT_CQ_T) {
	    printk("[stnovako] this is a CQ\n");
        ats_setup_virq(wpt, qp);
    }

    return ats_map_vqp(wpt, qp);
}

#ifdef MULTI_QP_PER_VHD
void wpt_update_dbvm_info(struct wpt *wpt, struct wpt_qp_data *d)
{
	int i;
	bool found = false;
	pid_t pid = d->vm_pid;
	int qid = d->q_id;

	printk("wpt_update_dbvm_info: VM = %d; this QID = %d\n", pid, qid);

	if (qid == 0)
		return;

	for (i = 0; i < wpt->ndbvms; i++) {
		if ((pid == wpt->dbvms[i].pid) && (qid == wpt->dbvms[i].qid)) {
			printk("found VM or QP\n");
			found = true;
			break;
		}
	}

	if (!found) {
		printk("Coperd,===>new QP entry===>DBVM[%d]\n", wpt->ndbvms);
		wpt->dbvms[wpt->ndbvms].pid = pid;
		wpt->dbvms[wpt->ndbvms].qid = qid;
		wpt->ndbvms++;
		return;
	}
}

#else

void wpt_update_dbvm_info(struct wpt *wpt, struct wpt_qp_data *d)
{
    int i;
    bool found = false;
    pid_t pid = d->vm_pid;

    for (i = 0; i < wpt->ndbvms; i++) {
        if (pid == wpt->dbvms[i].pid) {
            found = true;
            break;
        }
    }

    if (!found) {
        /* Coperd: this is a new DBVM, only safe for one vQP each DBVM, TODO */
        printk("Coperd,===>DBVM[%d] comes in\n", wpt->ndbvms);
        wpt->dbvms[wpt->ndbvms].pid = pid;
        wpt->dbvms[wpt->ndbvms].qid = wpt->ndbvms + 1;
        wpt->ndbvms++;
        return;
    }

    /* Coperd: if it's already there, no need to update info for now */
}
#endif

/* Coperd: register one QP at a time */
static int wpt_do_cmd_reg(unsigned long arg)
{
    int ret = 0;
    struct wpt *wpt = WPT();
    struct wpt_qp *qp;
    struct wpt_qp_data *data;
    size_t qpdsz = sizeof(struct wpt_qp_data);
    size_t qpsz = sizeof(struct wpt_qp);
    int qt, qid;

    data = kmalloc(qpdsz, GFP_KERNEL);
    if (!data) {
        return -ENOMEM;
    }

    if (copy_from_user(data, (void __user *)arg, qpdsz)) {
        ret = -EFAULT;
        goto err_copy_from_user;
    }

    qp = kmalloc(qpsz, GFP_KERNEL);
    if (!qp) {
        ret = -ENOMEM;
        goto err_copy_from_user;
    }
    qp->data = data;
    qid = data->q_id;
    qt = data->q_type;

    dump_wpt_qp_data(data);

    if (!wpt_is_q_type_valid(data)) {
        ret = -EINVAL;
        printk("Coperd,unknown queue type:%d\n", qt);
        goto err_invalid_qt;
    }

    wpt_update_dbvm_info(wpt, data);

    switch (qt) {
    case WPT_DB_T:
	    printk("[stnovako] registering DBell\n");
        ret = wpt_do_cmd_reg_db(wpt, qp);
        if (ret) {
            printk("Coperd,%s,do_cmd_reg_db() failed\n", __func__);
            goto err_reg_db;
        }
        break;
    case WPT_CQ_T:
	    printk("[stnovako] registering CQ\n");
        /* Coperd: remap pqps when a vCQ is registered */
        /* Coperd: TODO TODO */
        if (!client_mode_only) {
            ret = wpt_map_pqps(wpt, wpt->soc_va);
            if (ret) {
                goto err_map_pqps;
            }
        }
    case WPT_SQ_T:
	    printk("[stnovako] registering SQ\n");
        ret = wpt_do_cmd_reg_vqp(wpt, qp);
        if (ret) {
            printk("Coperd,%s,do_cmd_reg_vqp() failed\n", __func__);
            goto err_reg_vqp;
        }
        break;
    default:
        pr_err("Coperd,%s,Impossible!\n", __func__);
    }

    kfree(data);
    kfree(qp);

    return ret;

err_reg_vqp:
err_map_pqps:
    /* Coperd: need to restore original mapping here */
    /* Coperd: TODO TODO */
err_reg_db:
err_invalid_qt:
    kfree(qp);
err_copy_from_user:
    kfree(data);
    return ret;
}

static int wpt_do_cmd_unreg(unsigned long arg)
{
    int ret = 0;
    struct wpt *wpt = WPT();
    struct wpt_qp_data *data;
    struct wpt_qp *qp;
    size_t sz = sizeof(struct wpt_qp_data);
    size_t qpsz = sizeof(struct wpt_qp);

    printk("Coperd,%s,UNREG called\n", __func__);
    data = kmalloc(sizeof(struct wpt_qp_data), GFP_KERNEL);
    if (!data) {
        return -ENOMEM;
    }

    if (copy_from_user(data, (void __user *)arg, sz)) {
        ret = -EFAULT;
        goto err_copy_from_user;
    }

    qp = kmalloc(qpsz, GFP_KERNEL);
    if (!qp) {
        ret = -ENOMEM;
        goto err_copy_from_user;
    }
    qp->data = data;

    ats_disable_vqp(wpt->ats, qp);
    kfree(data);

    return 0;

err_copy_from_user:
    kfree(data);
    return ret;
}

struct pmap {
    u64 va;
    pte_t spte;
};

#define NPGS    4096
/* 16MB ==> 4096 4KB pages */
static struct pmap soc_pmap[NPGS];

/* Coperd: Do NOT change this */
static void wpt_verify_sp_map(struct wpt *wpt)
{
#define SP_MAGIC_IDX   (2000)
    const char *magic_str = "QuantumLeap";
    char *s = (char *)&wpt->spbuf[SP_MAGIC_IDX];
    strncpy(s, magic_str, strlen(magic_str));
}

/* Coperd: leap defined doorbells for ATS and SoC communications */
static int wpt_init_sp_page(struct wpt *wpt)
{
    struct page *page = alloc_page(GFP_KERNEL);
    if (!page) {
        return -ENOMEM;
    }

    wpt->sppage = page;
    wpt->sppfn = page_to_pfn(page);
    /* Coperd: leap uses 0-2047 bytes for should-poll communication */
    wpt->spbuf = vmap(&page, 1, VM_MAP, PAGE_KERNEL_NOCACHE);
    if (!wpt->spbuf) {
        return -1;
    }

    BUG_ON((unsigned long)wpt->spbuf % PAGE_SIZE);
    memset(wpt->spbuf, 0, PAGE_SIZE);

    /* Coperd: leap uses 2048-4095 bytes for should-interrupt communication */
    wpt->sibuf = (u32 *)(((void *)wpt->spbuf) + 2048);

    wpt_verify_sp_map(wpt);
    SetPageReserved(page);

    return 0;
}

static void wpt_free_sp_page(struct wpt *wpt)
{
    ClearPageReserved(wpt->sppage);
    __free_page(wpt->sppage);
    wpt->sppage = NULL;
    wpt->sppfn = WPT_INVALID_PFN;
    wpt->spbuf = NULL;
    wpt->sibuf = NULL;
}

/* Coperd: map should-poll page */
static int wpt_map_sp(struct wpt *wpt, unsigned long addr)
{
    struct vm_area_struct *vma = wpt->soc_vma;
    unsigned long pfn = wpt->sppfn;

    if (wpt_remap_pfns(wpt, vma, addr, pfn, PAGE_SIZE, vma->vm_page_prot)) {
        printk("Coperd,%s,map sppage to SoC failed\n", __func__);
        return -1;
    }

    return 0;
}

static int wpt_do_cmd_map(unsigned long arg)
{
    struct wpt *wpt = WPT();
    unsigned long cur_vaddr = arg, iter_vaddr = arg;
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma = find_vma(mm, arg);
    pte_t *ptep;
    int ret;
    int i;

    /* Coperd: save SoC side orignal page mapping first */
    for (i = 0; i < NPGS; i++) {
        BUG_ON(iter_vaddr % 4096 != 0);
        ptep = va2pte(mm, iter_vaddr);
        if (!ptep) {
            return -EFAULT;
        }

        soc_pmap[i].va = iter_vaddr;
        soc_pmap[i].spte = *ptep;

        pte_unmap(ptep);
        iter_vaddr += 4096;
    }

    /* Coperd: save mm struct of SoC for later remapping purpose */
    wpt->soc_mm = mm;
    wpt->soc_va = arg;
    wpt->soc_vma = vma;
    if (!wpt->soc_vma) {
        printk("Coperd,%s,couldn't find vma for addr:0x%lx\n", __func__, wpt->soc_va);
        return -1;
    }

    /* Coperd: use the last page for communicate sp information */
    iter_vaddr = arg + 16 * 1024 * 1024 - 4096;
    ret = wpt_map_sp(wpt, iter_vaddr);
    if (ret) {
        return -1;
    }

    /* Coperd: skip mapping pQPs if we only need to run socvm-client */
    if (!client_mode_only) {
        /* Coperd: map SQs and CQs */
        ret = wpt_map_pqps(wpt, cur_vaddr);
        if (ret) {
            return -1;
        }
    }

    return 0;
}

static int wpt_do_cmd_unmap(unsigned long arg)
{
    struct wpt *wpt = WPT();
    unsigned long iter_vaddr;
    struct vm_area_struct *vma = wpt->soc_vma;
    pte_t spte;
    unsigned long pfn;
    int i;

    printk("[stnovako] unmapping vQPs from the SoC VM");

    for (i = 0; i < NPGS; i++) {
        iter_vaddr = soc_pmap[i].va;
        spte = soc_pmap[i].spte;
        pfn = pte_pfn(spte);

        if (wpt_remap_pfns(wpt, vma, iter_vaddr, pfn, 4096, vma->vm_page_prot)) {
            printk("Coperd,%s,SoC unmap() failed\n", __func__);
        }
    }

    printk("Coperd,%s,unmap() Done ..\n", __func__);

    return 0;
}

#if 0
/* Coperd: obselete function used for OCSSD
static bool wpt_verify_bbtbl(struct nvme_nvm_bb_tbl *buf)
{
    if (buf->tblid[0] != 'B' || buf->tblid[1] != 'B' ||
            buf->tblid[2] != 'L' || buf->tblid[3] != 'T') {
        pr_err("Coperd,bbt format mismatch\n");
        return false;
    }

    if (le16_to_cpu(buf->verid) != 1) {
        pr_err("Coperd, bbt version not supported\n");
        return false;
    }

    if (le32_to_cpu(buf->tblks) != 1020 * 2) {
        pr_err("Coperd,bbt unsuspeted blocks returnd (%u!=%u)",
                le32_to_cpu(buf->tblks), 1020 * 2);
        return false;
    }

    return true;
}
#endif

static int wpt_do_cmd_passthru_identity(unsigned long addr)
{
    struct wpt *wpt = WPT();
    struct nvme_nvm_command c = {};
    void *idbuf;
    int ret;

    c.identity.opcode = ocadmin_identity;
    c.identity.nsid = cpu_to_le32(1);
    c.identity.chnl_off = 0;

    idbuf = kmalloc(4096, GFP_KERNEL);
    if (!idbuf)
        return -ENOMEM;

    ret = nvme_submit_sync_cmd(wpt->admin_q, (struct nvme_command *)&c, idbuf, 4096);
    if (ret) {
        pr_err("Coperd,OC identity passthru failed\n");
        ret = -EIO;
        goto out;
    }

    /* Coperd: copy data back to QEMU process */
    ret = copy_to_user((void __user *)addr, idbuf, 4096);
    if (ret) {
        ret = -EINVAL;
        goto out;
    }

    kfree(idbuf);
    return 0;

out:
    kfree(idbuf);
    return ret;
}

static int wpt_do_cmd_passthru_getbbtbl(unsigned long addr)
{
    struct wpt *wpt = WPT();
    struct nvme_nvm_command c = {};
    void *bbtbl_buf;
    struct wpt_admin_passthru_data pd;
    size_t pdsize = sizeof(struct wpt_admin_passthru_data);
    size_t bbtbl_sz = sizeof(struct nvme_nvm_bb_tbl) + 1020 * 2;
    int ret;

    c.get_bb.opcode = ocadmin_get_bbtbl;
    c.get_bb.nsid = cpu_to_le32(1);

    /* Coperd: copy the command */
    if (copy_from_user(&pd, (void __user *)addr, pdsize)) {
        ret = -EFAULT;
        return -1;
    }
    BUG_ON(current->pid != pd.vm_pid);

    c.get_bb.spba = ((struct nvme_nvm_command *)&(pd.c))->get_bb.spba;

    bbtbl_buf = kzalloc(bbtbl_sz, GFP_KERNEL);
    if (!bbtbl_buf)
        return -ENOMEM;

    ret = nvme_submit_sync_cmd(wpt->admin_q, (struct nvme_command *)&c,
            bbtbl_buf, bbtbl_sz);
    if (ret) {
        pr_err("Coperd,get_bbtbl passthru failed\n");
        ret = -EIO;
        goto out;
    }

    /* Coperd: copy data back to QEMU process */
    ret = copy_to_user((void __user *)pd.buf, bbtbl_buf, bbtbl_sz);
    if (ret) {
        ret = -EINVAL;
        goto out;
    }

    kfree(bbtbl_buf);
    return 0;

out:
    kfree(bbtbl_buf);
    return ret;
}

/* Coperd: passthru OCSSD admin commands from lightnvm running in DBVM */
/* Need support from host NVMe driver to expose the admin_q info */
#if 0
static int wpt_do_cmd_passthru(unsigned long addr)
{
    struct wpt *wpt = WPT();
    struct wpt_admin_passthru_data pd;
    size_t pdsize = sizeof(struct wpt_admin_passthru_data);
    struct nvme_nvm_command *c;
    u8 opc;
    u64 prp1_pfn, prp1_hpa;
    struct nvme_nvm_bb_tbl *buf; // reuse the one from DBVM
    struct page *buf_pg;
    int buflen = 0;
    struct kvm *kvm;
    int ret = 0;

    /* Coperd: copy the command */
    if (copy_from_user(&pd, (void __user *)addr, pdsize)) {
        ret = -EFAULT;
        return -1;
    }
    BUG_ON(current->pid != pd.vm_pid);
    kvm = get_kvm(current->pid);

    c = (struct nvme_nvm_command *)&(pd.c);
    opc = c->get_bb.opcode;

    switch (opc) {
    case ocadmin_identity:
        buflen = 4096;
        break;
    case ocadmin_get_bbtbl:
        buflen = sizeof(struct nvme_nvm_bb_tbl) + 1020 * 2;
        break;
    case ocadmin_set_bbtbl:
    default:
        printk("Coperd,%s,unsupported OC admin command\n", __func__);
        return -1;
    }

    prp1_hpa = ats_do_ats_one_addr(kvm, le64_to_cpu(c->get_bb.prp1));
    c->get_bb.prp1 = cpu_to_le64(prp1_hpa);
    prp1_pfn = prp1_hpa >> PAGE_SHIFT;
    buf_pg = pfn_to_page(prp1_pfn);

    buf = vmap(&buf_pg, 1, VM_MAP | VM_IOREMAP, PAGE_KERNEL_NOCACHE);
    if (!buf) {
        return -EFAULT;
    }

    /* Coperd: what if buf is not page aligned */
    buf += prp1_hpa % PAGE_SIZE;

    ret = nvme_submit_sync_cmd(wpt->admin_q, (struct nvme_command *)c, buf,
            buflen);
    if (ret) {
        pr_err("Coperd,ocssd admin (0x%x) failed (%d)\n", opc, ret);
        ret = -EIO;
        goto out;
    }

    if (opc == ocadmin_get_bbtbl) {
        if (!wpt_verify_bbtbl(buf)) {
            goto out;
        }
    }

    /* Coperd: need to return the CQE directly, but how?? */
    /* TODO TODO TODO */

out:
    /* Coperd: it doesn't belong to us, let it go */
    vunmap(buf);
    return ret;
}
#endif

static long wpt_ioctl(struct file *filp, unsigned int cmd, unsigned long vaddr)
{
    unsigned long cur_addr = vaddr;

    switch(cmd) {

    case WPT_CMD_DUMP:
	    printk("[WPT_CMD_DUMP]\n");
        return wpt_do_cmd_dump(vaddr);

    case WPT_CMD_SWAP:
	    printk("[WPT_CMD_SWAP]\n");
        return wpt_do_cmd_swap(vaddr);

    case WPT_CMD_REG:
	    printk("[WPT_CMD_REG]\n");
        return wpt_do_cmd_reg(vaddr);

    case WPT_CMD_UNREG:
	    printk("[WPT_CMD_UNREG]\n");
        return wpt_do_cmd_unreg(vaddr);

    case WPT_CMD_MAP:
	    printk("[WPT_CMD_MAP]\n");
        return wpt_do_cmd_map(vaddr);

    case WPT_CMD_UNMAP:
	    printk("[WPT_CMD_UNMAP]\n");
        return wpt_do_cmd_unmap(vaddr);

    case WPT_CMD_MAP_PDB:
	    printk("[WPT_CMD_MAP_PDB]\n");
        return wpt_map_pqp_db(&cur_addr);

    case WPT_CMD_GET_PDB:
	    printk("[WPT_CMD_GET_PDB]\n");
        return wpt_get_pqp_db(vaddr);

    case WPT_CMD_ATS:
	    printk("[WPT_CMD_ATS]\n");
        return wpt_do_cmd_ats(vaddr);

    /* Coperd: admin command passthru */
    case WPT_CMD_ADMIN_PASSTHRU_GETBBTBL:
        return wpt_do_cmd_passthru_getbbtbl(vaddr);

    case WPT_CMD_ADMIN_PASSTHRU_IDENTITY:
        return wpt_do_cmd_passthru_identity(vaddr);

    default:
        return -ENOTTY;
    }
}

const struct file_operations wpt_fops = {
    .owner = THIS_MODULE,
    .open = wpt_open,
    .read = wpt_read,
    .write = wpt_write,
    .mmap = wpt_mmap,
    .release = wpt_release,
    .unlocked_ioctl = wpt_ioctl
};

static void wpt_nvme_sanity_check(void)
{
    BUG_ON(sizeof(struct nvme_command) != NVME_SQE_SZ);
    BUG_ON(sizeof(struct nvme_common_cmd) != NVME_SQE_SZ);
    BUG_ON(sizeof(struct nvme_rw_cmd) != NVME_SQE_SZ);
    BUG_ON(sizeof(struct nvme_ocrw_cmd) != NVME_SQE_SZ);
    BUG_ON(sizeof(struct nvme_cmd) != NVME_SQE_SZ);
    BUG_ON(sizeof(struct nvme_nvm_command) != NVME_SQE_SZ);
    BUG_ON(sizeof(struct nvme_nvm_identity) != NVME_SQE_SZ);
    BUG_ON(sizeof(struct nvme_nvm_getbbtbl) != NVME_SQE_SZ);
    BUG_ON(sizeof(struct nvme_nvm_setbbtbl) != NVME_SQE_SZ);

    BUG_ON(sizeof(struct nvme_completion) != NVME_CQE_SZ);
}

/* Coperd: TODO: to optimize */
static void wpt_init_pqp_buf(void)
{
    qpbufp = qpbuf;
}

static void wpt_alloc_dmabuf(void)
{
    u64 tt_bytes = (4ULL << 30);
    void *tbuf;
    struct wpt *wpt = WPT();
    u64 prev_pa, cur_pa;
    int npgs = tt_bytes / PAGE_SIZE + 1;
    int i;

    printk("Coperd,wpt trying to alloc [%d] cont. physical pages ..\n", npgs);
    wpt->dmabuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    tt_bytes -= PAGE_SIZE;
    prev_pa = virt_to_phys(wpt->dmabuf);
    i = 1;

    for (; i <= npgs; i++) {
        tbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
        cur_pa = virt_to_phys(tbuf);
        printk("Coperd,cur_pa=%llx,prev_pa=%llx\n", cur_pa, prev_pa);
        if (cur_pa != (prev_pa + PAGE_SIZE)) {
            goto err;
        }

        prev_pa = cur_pa;
        tt_bytes -= PAGE_SIZE;
        if (i % 1000 == 0) {
            printk("Coperd, done [%d] pages now ..\n", i);
        }
    }

    printk("Coperd,wpt alloc 4G dmabuf success,at 0x%llx\n", virt_to_phys(wpt->dmabuf));

err:
    /* TODO */
    printk("Coperd,%s,failed at [%d]-th pg allocation\n", __func__, i);
}

int wpt_ap(void *arg)
{
    wpt_alloc_dmabuf();

    return 0;
}

int wpt_ap_thread(void)
{
    struct task_struct *t;

    return 0;

    t = kthread_create(wpt_ap, NULL, "WPT-ap-thrd");
    if (IS_ERR(t)) {
        int err = PTR_ERR(t);
        printk("Coperd,err,%d\n", __LINE__);
        return err;
    }

    wake_up_process(t);

    return 0;
}

static int wpt_read_proc(struct seq_file *seq, void *val)
{
    printk("Coperd,%s triggered\n", __func__);

    return 0;
}

static int wpt_read_open(struct inode *inode, struct file *file)
{
    return single_open(file, wpt_read_proc, inode->i_private);
}

static ssize_t wpt_write_proc(struct file *file, const char __user *buffer,
        size_t count, loff_t *ppos)
{
    struct wpt *wpt = WPT();
    char *ubuf;
    char *ip_str, *port_str;
    int r;
    int i;

    printk("Coperd,%s,called\n", __func__);

    /* Coperd: only do RDMA when needed */
    if (!use_rdma_for_vqp) {
        printk("Coperd,%s,Do nothing as use_rdma_for_vqp=%d\n", __func__,
                use_rdma_for_vqp);
        return count;
    }

#if 0
    if (!try_module_get(THIS_MODULE))
        return -ENODEV;
#endif

    ubuf = kmalloc(count, GFP_KERNEL);
    if (ubuf == NULL) {
        pr_err("Coperd,%s,kmalloc failed\n", __func__);
        return -EFAULT;
    }

    if (copy_from_user(ubuf, buffer, count)) {
        pr_err("Coperd,copy user data buf failed\n");
        kfree(ubuf);
        return count;
    }

    ubuf[count - 1] = 0;
    printk("Coperd,%s,proc write: %s\n", __func__, ubuf);

    ip_str = strsep(&ubuf, ":");
    port_str = strsep(&ubuf, ":");

    if (!ip_str || !port_str) {
        pr_err("Coperd, Error, /proc/wpt format: 192.168.88.89:9999\n");
        return count;
    }

    r = kstrtouint(port_str, 10, &pport);
    if (r) {
        pr_err("Coperd,%s,kstrtol error\n", __func__);
        return count;
    }
    printk("Coperd,ip_str:%s,port_str:%s,pport:%d\n", ip_str, port_str, pport);

    /* Coperd: create one RDMA connection for each DBVM */
    for (i = 0; i < NR_DBVMS; i++) {
        /* Coperd: take care of byte order here */
        struct nvme_qpair *vqp = &wpt->ats->vqps[i];
        struct rctx *rctx = &wpt->rctxs[i];

        rctx->port = htons(pport + i);
        strcpy(rctx->addr_str, ip_str);
        rctx->rid = i;
#ifdef RDMA_VQPS
        wpt_rdma_init(rctx);
#endif

        /* Coperd: associate vqp with rdma context */
        BUG_ON(IS_ERR(vqp));
        vqp->rctx = rctx;
        rctx->vqp = vqp;
        BUG_ON(vqp->rctx == NULL);
#ifdef RDMA_VQPS
        wpt_setup_wrs(vqp->rctx);
        /* Let's post all the initial recvs here */
        wpt_post_initial_recvs(vqp->rctx);
#endif
    }

    kfree(ubuf);
#if 0
    module_put(THIS_MODULE);
#endif

    printk("Coperd,%s,end\n", __func__);

    /* Coperd: should return number of successful "written" bytes */
    return count;
}


void wpt_deinit()
{
#ifdef RDMA_VQPS			
	int i = 0;
	struct wpt *wpt = WPT();

	for (i = 0; i < NR_DBVMS; i++) {
		struct rctx *rctx = &wpt->rctxs[i];

		wpt_rdma_deinit(rctx);

		printk("[ql] disconnected VM %u\n", i);
	}
#endif
}

static struct file_operations wpt_ops = {
	.owner = THIS_MODULE,
	.open = wpt_read_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write = wpt_write_proc,
};

static int wpt_create_proc_entry(void)
{
	wpt_proc = proc_create("wpt", 0777, NULL, &wpt_ops);
	if (wpt_proc == NULL) {
		pr_err("Coperd,cannot create /proc/wpt\n");
		return -ENOMEM;
	}

    return 0;
}

static int wpt_destroy_proc_entry(void)
{
    remove_proc_entry("wpt", NULL);
    return 0;
}

static int __init wpt_init(void)
{
    struct wpt *wpt;
    struct wpt_dev *wpt_dev;
    struct wpt_dev_data *wpt_dev_data;
    int nr_cpus = num_possible_cpus();
    int i = 0;
    int ret;

    wpt_nvme_sanity_check();

    if (pin_to >= nr_cpus) {
        printk("WPT told to pin ATS to [%d], but only have %d cores\n",
                pin_to, nr_cpus);
        return -EINVAL;
    }

    wpt = kzalloc(sizeof(struct wpt), GFP_KERNEL);
    if (!wpt) {
        return -ENOMEM;
    }
    gwpt = wpt;


    wpt_dev_data = wpt->wpt_dev_data;
    wpt_dev = wpt->wpt_dev;

    ret = register_chrdev_region(MKDEV(WPT_MAJOR, 0), WPT_MAX_MINORS,
            "wpt_driver");
    if (ret) {
        goto err_register_chrdev;
    }

    for (i = 0; i < WPT_MAX_MINORS; i++) {
        /* initialize devs fields */
        cdev_init(&wpt_dev_data[i].cdev, &wpt_fops);
        cdev_add(&wpt_dev_data[i].cdev, MKDEV(WPT_MAJOR, i), 1);
    }

    printk("Coperd,===>Registered wpt char dev at MAJOR: %d\n", WPT_MAJOR);

    ret = wpt_dev_init(wpt);
    if (ret) {
        goto err_dev_init;
    }

    ret = wpt_qpair_meta_init(wpt);
    if (ret) {
        ret = -ENOMEM;
        goto err_qpair_meta_init;
    }

    ret = wpt_init_sp_page(wpt);
    if (ret) {
        goto err_init_sp_page;
    }

    /* Coperd: grab the pQP handle here */
    wpt_init_pqp_buf();
    wpt->admin_q = admin_qp;
    wpt->data_shift = qpbufp[0].lba_shift;
    wpt->mdts = 4096 * (1 << qpbufp[0].mdts);
    wpt->leap_nr_pqps = qpbuf[0].nr_io_queues_leap;
    //wpt->mdts = 4096 * (1 << 5);

#if 0
    /* Coperd: HACK for OCSSD for now, TODO TODO TODO TOFIX */
    wpt->data_shift = 12;
    wpt->mdts = 4096 * (1 << 6);
#endif

    if (client_mode_only) {
        /* Fake some numbers */
        wpt->data_shift = 12;
        wpt->mdts = 4096 << 5;
        wpt->leap_nr_pqps = 16;
    }

    if (wpt->data_shift != 12) {
        printk(KERN_ALERT "\n\n---------------------------------------------\n");
        printk(KERN_ALERT "Only 4KB sector size supported, but 512B detected\n");
        printk(KERN_ALERT "-------------------------------------------------\n");
    }

    WARN_ON(wpt->leap_nr_pqps == 0);

    printk("Coperd,data_shift=%d,mdts=%d,leap_nr_pqps=%d\n", wpt->data_shift,
            wpt->mdts, wpt->leap_nr_pqps);

    ret = ats_init_ats(wpt);
    if (ret) {
        goto err_ats_init_ats;
    }

    /* Kick start ATS thread */
    ret = ats_init_poller(wpt);
    if (ret) {
        goto err_ats_poller_init;
    }

    wpt_ap_thread();

    /* Coperd: create proc interface for RDMA control */
    wpt_create_proc_entry();
    printk("Coperd,use_rdma_for_vqp=%d,client_mode_only=%d,use_soc=%d\n",
            use_rdma_for_vqp, client_mode_only, use_soc);

    return 0;

err_ats_poller_init:
    ats_free_ats(wpt);
err_ats_init_ats:
    wpt_free_sp_page(wpt);
err_init_sp_page:
    wpt_qpair_meta_free(wpt->qpair_meta);
err_qpair_meta_init:
    wpt_dev_free(wpt);
err_dev_init:
    unregister_chrdev_region(MKDEV(WPT_MAJOR, 0), WPT_MAX_MINORS);
err_register_chrdev:
    kfree(wpt);

    return ret;
}

static void wpt_exit(void)
{
    int i;
    struct wpt *wpt = WPT();
    struct wpt_dev_data *wpt_dev_data = wpt->wpt_dev_data;
    struct wpt_qpair_meta *qpair_meta = wpt->qpair_meta;

    wpt_destroy_proc_entry();

    ats_stop_poller(wpt);
    ats_free_ats(wpt);
    wpt_free_sp_page(wpt);
    wpt_qpair_meta_free(qpair_meta);
    wpt_dev_free(wpt);

    for (i = 0; i < WPT_MAX_MINORS; i++) {
        /* release devs fields */
        cdev_del(&wpt_dev_data[i].cdev);
    }
    unregister_chrdev_region(MKDEV(WPT_MAJOR, 0), WPT_MAX_MINORS);


    kfree(wpt);
    printk("Coperd,===>Unregistered wpt char dev\n");
}

module_init(wpt_init);
module_exit(wpt_exit);

MODULE_AUTHOR("Huaicheng Li <huaicheng@cs.uchicago.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernel driver for LeapIO project");
MODULE_VERSION("0.1");
