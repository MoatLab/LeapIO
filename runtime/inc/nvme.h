#ifndef __NVME_H
#define __NVME_H

#include <linux/types.h>
#include <stdint.h>
#include <stdbool.h>
#include "queue.h"
#include "rte_ring.h"

#include "qls_azure_drive.h"

#define NVME_CMD_SZ     (64)
#define NVME_CPL_SZ     (16)

#define NVME_CMD_FLUSH  0x0
#define NVME_CMD_WRITE  0x1
#define NVME_CMD_READ   0x2

enum {
    NVM_PLANE_SINGLE = 1,
    NVM_PLANE_DOUBLE = 2,
    NVM_PLANE_QUAD   = 4,

    /* OC opcode */
    NVM_OP_PWRITE    = 0x91,
    NVM_OP_PREAD     = 0x92,
    NVM_OP_ERASE     = 0x90,

    /* PPA Command Flags */
    NVM_IO_SNGL_ACCESS = 0x0,
    NVM_IO_DUAL_ACCESS = 0x1,
    NVM_IO_QUAD_ACCESS = 0x2,

    /* NAND Access Modes */
    NVM_IO_SUSPEND      = 0x80,
    NVM_IO_SLC_MODE     = 0x100,
    NVM_IO_SCRAMBLE_ENABLE  = 0x200,
};

struct nvme_completion {
	union nvme_result {
		uint16_t u16;
		uint32_t u32;
		uint64_t u64;
	} result;
	uint16_t sq_head;   /* how much of this queue may be reclaimed */
	uint16_t sq_id;		/* submission queue that generated this entry */
	uint16_t cid;       /* of the command which completed */
	uint16_t status;	/* did the command fail, and if so, why? */
};

struct nvme_sgl_desc {
	uint64_t addr;
	uint32_t length;
	uint8_t	rsvd[3];
	uint8_t	type;
};

struct nvme_keyed_sgl_desc {
	uint64_t addr;
	uint8_t length[3];
	uint8_t key[4];
	uint8_t type;
};

union nvme_data_ptr {
	struct {
		uint64_t prp1;
		uint64_t prp2;
	};
	struct nvme_sgl_desc	sgl;
	struct nvme_keyed_sgl_desc ksgl;
};

/* Coperd: NVMe command format used by QEMU */
struct nvme_cmd {
    uint8_t     opcode;
    uint8_t     fuse;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    res1;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint32_t    cdw10;
    uint32_t    cdw11;
    uint32_t    cdw12;
    uint32_t    cdw13;
    uint32_t    cdw14;
    uint32_t    cdw15;
};

struct nvme_common_command {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint32_t    cdw2[2];
    uint64_t    metadata;
    union nvme_data_ptr	dptr;
    uint32_t    cdw10[6];
};

struct nvme_rw_command {
    uint8_t     opcode;
    uint8_t     flags;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    mptr;
    uint64_t    prp1;
    uint64_t    prp2;
    uint64_t    slba;
    uint16_t    nlb;
    uint16_t    control;
    uint32_t    dsmgmt;
    uint32_t    reftag;
    uint16_t    apptag;
    uint16_t    appmask;
};

struct nvme_oc_rw {
    uint8_t opcode;
    uint8_t flags;
    uint16_t command_id;
    uint32_t nsid;
    uint64_t rsvd2;
    uint64_t metadata;
    uint64_t prp1;
    uint64_t prp2;
    uint64_t spba;
    uint16_t length;
    uint16_t control;
    uint32_t dsmgmt;
    uint64_t resv;
};

struct nvme_command {
    union {
        struct nvme_cmd c;
        struct nvme_oc_rw ocrw;
        struct nvme_common_command common;
        struct nvme_rw_command rw;
    };
};

enum req_status {
    IN_REQ_LIST = 0,
    IN_SUBMITTER_P_LIST = 1,
    IN_COMPLETER_P_LIST = 2,
    IN_CPL_P_LIST = 3,
};

typedef struct nvme_req {
    struct nvme_qpair *qp;
    /* parts maintained by submitter */
    struct nvme_command cmd;
    /* cid is used to save the original cmd->cid used in cmd */
    int cid;

    /* Regarding iov:
     *
     * for client, it maps prp list into iov (HPA -> SoC VM GVA), the buffer is
     * already allocated by DB-VM, so no need to touch it, we only use/map it
     *
     * for server, it needs to allocate iov space for holding data received from
     * client and change/fill vcmd prp list before submitting it to pQP so that
     * physical SSD can do DMA into server DRAM correctly. We reserve a range of
     * host physical memory and dedicate it for DMA, all the iov are allocated
     * there
     */
    struct iovec *iov;
    int iovcnt;
    int cmd_bytes;
    int data_bytes;

    /* parts mantained by completer */
    struct nvme_completion cpl;

    /* can be in {req_list, send_pending_list, recv_pending_list} */
    QTAILQ_ENTRY(nvme_req) entry;
    /* id is equal to cmd->cid so we can easily match cpl to cmd */
    int id;

    /* common for both submitter and completer */
    int len;
    bool is_write;
    int cur_iov_idx;
    int cur_iov_oft;
    enum req_status status;

    /* Prealloc'ed buffer for use with RDMA */
    struct iovec *riov;
    int riovcnt;
    int rbuflen;
    void *rbuf; /* recv buf */

    struct iovec *siov;
    int siovcnt;
    int sbuflen;
    void *sbuf; /* send buf */

    /* For vQP routing */
    void *cmdbuf;
    void *cplbuf;
} nvme_req;

/* Coperd: NVMe queue, we use this to describe either a vQP or pQP */
struct nvme_qpair {
    volatile struct nvme_command *sq_cmds;
    volatile struct nvme_completion *cqes;
    volatile uint32_t *sq_db; /* Coperd: either shadow DB for vQP or DB for pQP */
    volatile uint32_t *cq_db;
    volatile uint8_t *sp_db; /* Coperd: should_poll doorbell */
    volatile uint32_t *si_db; /* Coperd: should_interrupt doorbell */
    volatile uint32_t *sq_ei;
    volatile uint32_t *cq_ei;
    uint16_t q_depth;
    uint16_t qid;

    uint16_t sq_tail;
    uint16_t cq_head;
    uint8_t cq_phase;

    /* Coperd: for vQP only, needed by controller logic */
    uint16_t sq_head;
    uint16_t cq_tail;

    uint8_t prev_spv;
    bool need_reset;
    /* Coperd: to protect vcq state across vqp reset */
    pthread_mutex_t lock;

    struct leap *leap;
    struct rdma_context *rctx;

    nvme_req *reqs;
    QTAILQ_HEAD(,nvme_req) req_list;
    QTAILQ_HEAD(,nvme_req) submitter_pending_req_list;
    QTAILQ_HEAD(,nvme_req) completer_pending_req_list;
    QTAILQ_HEAD(,nvme_req) cpl_pending_req_list;
    nvme_req *cur_send_cmd_req;
    nvme_req *cur_send_cmd_data_req;
    nvme_req *cur_recv_cpl_req;
    nvme_req *cur_recv_cpl_data_req;

    /* for client: completer use */
    struct nvme_completion cpl; /* nvme completion place holder */
    /* for server: submitter use */
    struct nvme_command cmd; /* cmd place holder */
    /* for client: CMD (64B); for server: CPL (16B) */
    int cmd_bytes;

    nvme_req *cur_recv_req;

    /* submitter to completer lockless req queue */
    struct rte_ring *s2c_rq;
    /* completer to submitter lockless req queue */
    struct rte_ring *c2s_rq;
    QTAILQ_HEAD(,nvme_req) s2c_list;
    QTAILQ_HEAD(,nvme_req) c2s_list;

    int cmd_sockfd;
    int data_sockfd;

	int role;
	quantum_leap::qls_azure_drive* m_drive;
};

enum nvme_status_code {
    NVME_SUCCESS            = 0x0000,
    NVME_INVALID_OPCODE     = 0x0001,
    NVME_INVALID_FIELD      = 0x0002,
    NVME_CID_CONFLICT       = 0x0003,
    NVME_DATA_TRAS_ERROR    = 0x0004,
    NVME_CMD_ABORT_REQ      = 0x0007,
    NVME_INVALID_NSID       = 0x000b,
    NVME_LBA_RANGE          = 0x0080,
    NVME_INVALID_CQID       = 0x0100,
    NVME_INVALID_QID        = 0x0101,
    NVME_WRITE_FAULT        = 0x0280,
    NVME_DNR                = 0x4000,
    NVME_NO_COMPLETE        = 0xffff,
};

struct leap_qpbuf {
	int qid;
	int q_depth;
	uint64_t sq_paddr;   /* SQ physical address */
	uint64_t cq_paddr;   /* CQ physical address */
	uint64_t db_paddr;   /* Doorbell physical address */
	int stride;
	int lba_shift;
	int mdts;
	int nr_io_queues_leap;
};

struct leap_qpbuf_socp {
    int qid;
    int q_depth;
    volatile void *sqbuf;
    volatile void *cqbuf;
    volatile uint32_t *sqdb;
    volatile uint32_t *cqdb;
};

#define MAX_QPBUF (256)


#endif
