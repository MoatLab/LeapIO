/*
 * File rt.c - RDMA testing for LeapIO
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
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

unsigned int pport = 9999;
module_param(pport, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(pport, "Port to connect to");

static struct proc_dir_entry *wpt_proc;

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

struct rctx {
    struct rdma_cm_id *cm_id;

    struct list_head list;
    struct ib_cq *cq;
    struct ib_pd *pd;
    struct ib_mr *dma_mr;
    struct ib_qp *qp;

    u16 port;
    u8 addr[16];
    char *addr_str;

    struct ib_recv_wr rq_wr;
    struct ib_send_wr sq_wr;

    enum rctx_state state;
    wait_queue_head_t sem;
};

static struct rctx rctxs[16];
static struct rctx *rctx;

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

    init_attr.cap.max_send_wr = 1024;
    init_attr.cap.max_recv_wr = 1024;
    init_attr.cap.max_recv_sge = 8;
    init_attr.cap.max_send_sge = 8;

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

static void cq_event_handler(struct ib_cq *cq, void *ctx)
{
    struct rctx *rctx = (struct rctx *)ctx;
    int r;
    struct ib_wc wc;
    struct ib_recv_wr *bad_wr;

    BUG_ON(rctx->cq != cq);

    ib_req_notify_cq(rctx->cq, IB_CQ_NEXT_COMP);

    while ((r = ib_poll_cq(rctx->cq, 1, &wc)) == 1) {
        printk("Coperd,%s,recv sth ...\n", __func__);
        if (wc.status) {
            pr_err("Coperd,cq completion failed with id: %Lx status %d opc %d"
                    "vendor_err %x\n", wc.wr_id, wc.status, wc.opcode, wc.vendor_err);
            return;
        }

        switch (wc.opcode) {
        case IB_WC_RECV:
            printk("Coperd,recv %d bytes\n", wc.byte_len);

            r = ib_post_recv(rctx->qp, &rctx->rq_wr, &bad_wr);
            if (r) {
                pr_err("Coperd,post recv errno:%d\n", r);
                return;
            }
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

    r = ib_req_notify_cq(rctx->cq, IB_CQ_NEXT_COMP);
    if (r) {
        pr_err("Coperd,%s,ib_req_notify_cq failed\n", __func__);
    }

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

static int rt_init(struct rctx *rctx)
{
    int r;
    struct ib_recv_wr *bad_wr;
    struct sockaddr_storage sin;
    struct rdma_conn_param conn_param;

    printk("Coperd,%s,start\n", __func__);

    rctx->state = IDLE;
    init_waitqueue_head(&rctx->sem);

    rctx->cm_id = rdma_create_id(&init_net, cm_event_handler, rctx, RDMA_PS_TCP,
            IB_QPT_RC);
    if (IS_ERR(rctx->cm_id)) {
        r = PTR_ERR(rctx->cm_id);
        pr_err("rdma_create_id error: %d\n", r);
    }

    rctx->port = htons(pport);
    rctx->addr_str = "192.168.88.89";
    in4_pton(rctx->addr_str, -1, rctx->addr, -1, NULL);
    printk("Coperd,server info: %s [%d]\n", rctx->addr_str, ntohs(rctx->port));

    /* Coperd: bind to local RDMA dev */
    fill_sockaddr(&sin, rctx);

    r = rdma_resolve_addr(rctx->cm_id, NULL, (struct sockaddr *)&sin, 2000);
    if (r) {
        pr_err("Coperd,rdma_resolve_addr error:%d\n", r);
        return r;
    }

    /* Coperd: need to wait here until ROUTE_RESOLVED */
    wait_event_interruptible_timeout(rctx->sem, rctx->state >= ROUTE_RESOLVED,
            msecs_to_jiffies(500));
    if (rctx->state != ROUTE_RESOLVED) {
        pr_err("Coperd,route not resolved!\n");
        return -EINTR;
    }
    printk("Coperd,done rdma_resolve_addr\n");

    if (!reg_supported(rctx->cm_id->device)) {
        pr_err("Coperd,RDMA dev doesn't support mem reg\n");
        return -EINVAL;
    }

    r = setup_qp(rctx, rctx->cm_id);
    if (r) {
        pr_err("Coperd, setup_qp() failed:%d\n", r);
        return r;
    }
    printk("Coperd,done setup_qp\n");

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
        pr_err("Coperd,rdma_connect() failed:%d\n", r);
        return r;
    }

    printk("Coperd,waiting to be connected\n");
    wait_event_interruptible_timeout(rctx->sem, rctx->state >= CONNECTED,
            msecs_to_jiffies(500));
    if (rctx->state == ERROR) {
        pr_err("Coperd,rctx in error state!\n");
        return -1;
    }

    printk("Coperd,%s,connected!\n", __func__);

    printk("Coperd,%s,end\n", __func__);

    return 0;
}

static int wpt_read_proc(struct seq_file *seq, void *v)
{
    printk("Coperd,%s triggered\n", __func__);

    return 0;
}

static int wpt_read_open(struct inode *inode, struct file *file)
{
    return single_open(file, wpt_read_proc, inode->i_private);
}

/*
 * Write proc is used to start a ping client or server.
 */
static ssize_t wpt_write_proc(struct file * file, const char __user * buffer,
        size_t count, loff_t *ppos)
{
    char *cmd;

    printk("Coperd,%s,called\n", __func__);

    if (!try_module_get(THIS_MODULE))
        return -ENODEV;

    cmd = kmalloc(count, GFP_KERNEL);
    if (cmd == NULL) {
        pr_err("Coperd,%s,kmalloc failed\n", __func__);
        return -EFAULT;
    }

    cmd[count - 1] = 0;
    printk("Coperd,%s,proc write: %s\n", __func__, cmd);

    rt_init(rctx);

    kfree(cmd);
    module_put(THIS_MODULE);

    printk("Coperd,%s,end\n", __func__);

    return count;
}

static struct file_operations wpt_ops = {
	.owner = THIS_MODULE,
	.open = wpt_read_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write = wpt_write_proc,
};

static int __init rt_module_init(void)
{
    /* Only use one for example */
    rctx = &rctxs[0];

	wpt_proc = proc_create("wpt", 0777, NULL, &wpt_ops);
	if (wpt_proc == NULL) {
		pr_err("Coperd,cannot create /proc/wpt\n");
		return -ENOMEM;
	}

    printk("Coperd,RDMA module inited\n");

    return 0;
}

static void __exit rt_module_exit(void)
{
    remove_proc_entry("wpt", NULL);

    printk("Coperd,RDMA module exited\n");
}

module_init(rt_module_init);
module_exit(rt_module_exit);

MODULE_AUTHOR("Huaicheng Li <huaicheng@cs.uchicago.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel level RDMA test driver, adapted from krping");
MODULE_VERSION("0.1");
