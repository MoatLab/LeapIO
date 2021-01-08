/* 
 * socp - offloaded SSD virtualization engine for LeapIO project, it runs on
 * both a SoC-like VM and real BRCM-SVK SoC
 *
 * Copyright (C) University of Chicago 2018-2020
 * Author: Huaicheng Li <huaicheng@cs.uchicago.edu>
 *
 * socp Responsibilities:
 *  - resources management
 *      - vQP, pQP, shadow DB, physical DB mapping
 *      - dynamic resource mapping notification
 *      - support multi-VMs, each VM w/ multi-vNVMe dev, each dev w/ multi-vQPs
 *  - NVMe queue management:
 *      - vQP processing as 'controller'
 *      - pQP as 'driver'
 *      - vQP-pQP mapping logic: queue level, request level
 *  - polling interface
 *  - services/features:
 *      - QoS, QP-based I/O scheduling
 *      - local NVMe SSD virtualization (for both regular and OpenChannel SSDs)
 *      - sub request management
 *      - NVMe-oF (RDMA / TCP / REST-API)
 *      - RAID 0/1
 *      - storage caching
 *      - Snapshot, etc.
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

#include <unordered_map>
#include <functional>

#include "inc/bswap.h"
#include "inc/barrier.h"
#include "inc/mmio.h"
#include "inc/nvme.h"
#include "inc/leap.h"
#include "inc/queue.h"
#include "globals.h"
#include "tcp.h"
#include "rdma.h"
#include "rdma-util.h"

//#define DEBUG_VQP
//#define DEBUG_PQP
//#define DEBUG_RTE_RING

//#define PSCHEDULE
//#define SNAPSHOTS
//#define CORE_IOPS_TEST
//#define ABC

#define MULTI_QP_PER_VHD

#ifdef ABC
#include "abc.h"
#endif

#define RES_SZ          (16ULL * MB) // (16 * MB) BAR-host-AS: 128GB
/* RES_QPSZ: the first 16MB is used for mapping queue pairs */
#define RES_QPSZ        (16 * MB)
#define RES0_SZ         (4096)
#define SHADOW_DB_OFT   (0)
#define SHADOW_DB_SZ    (4096 * MAX_NR_VQPS)
#define VQP_OFT         (SHADOW_DB_OFT + SHADOW_DB_SZ)
#define VSQ_SZ          (64 * KB)
#define VCQ_SZ          (16 * KB)
#define VQP_SZ          (VSQ_SZ + VCQ_SZ)

/* Coperd: TODO later */
#define PRES_OFT        (8 * MB)
/* Coperd: relative offset to PQP base addr */
#define PDB_OFT         (0)
#define PDB_SZ          (4096)
#define PSQ_OFT         (PDB_OFT + PDB_SZ)
#define PCQ_OFT         (4 * MB)
/* Coperd: right now, we create one extra set of pQPs in host NVMe driver */
#define NR_PQP          (NR_HOST_CPUS)
#define PSQ_SZ          (64 * KB)
#define PCQ_SZ          (16 * KB)
#define PQP_SZ          (PSQ_SZ + PCQ_SZ)

/* Coperd: for now, only one VM is supported */
#define RESNAME0        "/sys/devices/pci0000:00/0000:00:06.0/resource1"
#define RESNAME         "/sys/devices/pci0000:00/0000:00:06.0/resource4"

#ifdef PSCHEDULE
// constants for priority scheduling
#define PR0 10000
#define PR1 50
#define RETRY 10000000

// macros for getting min and max
#define get_max(a,b) \
	({ __typeof__ (a) _a = (a); \
		__typeof__ (b) _b = (b); \
		_a > _b ? _a : _b; })

#define get_min(a,b) \
	({ __typeof__ (a) _a = (a); \
		__typeof__ (b) _b = (b); \
		_a > _b ? _b : _a; })

#endif

//#define DEBUG_SOCP

#ifdef DEBUG_SOCP
#define debug(f_, ...)printf((f_), ##__VA_ARGS__);
#else
#define debug(fmt, args...)
#endif

static int resfd0 = -1;
static int resfd = -1;
static void *res_ptr0 = NULL;
static void *res_ptr = NULL;

#ifdef SNAPSHOTS
using namespace std;

struct pair_hash {
	template <class T1, class T2>
		std::size_t operator () (const std::pair<T1,T2> &p) const {
		auto h1 = std::hash<T1>{}(p.first);
		auto h2 = std::hash<T2>{}(p.second);

		return h1 ^ h2;
	}
};

static unordered_map<pair<unsigned long, unsigned long>, struct nvme_req *, pair_hash> log_reqs;
static unsigned long log_len = 0;
#endif

using namespace std;
static unordered_map<unsigned long, int> hash_cache;

static inline void *get_sp_db_base();
//static void server_reset_req(nvme_req *req);
static void server_prep_cmd(struct nvme_qpair *pqp, nvme_req *req);

void print_nvmecmd(struct nvme_command *cmd)
{
    struct nvme_rw_command *rw = &(cmd->rw);
    printf("opc:%d,cid:%d,slba:0x%lx,len:%d,prp1:0x%" PRIx64 ",prp2:0x%" PRIx64 "\n",
            rw->opcode, rw->cid, rw->slba, rw->nlb + 1, rw->prp1, rw->prp2);
}

void print_nvmecqe(volatile struct nvme_completion *cqe)
{
    printf("sq_head=%d,sq_id=%d,cid=%d,status=%d\n", cqe->sq_head, cqe->sq_id,
            cqe->cid, cqe->status);
}

static int get_resfd(void)
{
    if (resfd > 0)
        return resfd;

    resfd = open(RESNAME, O_RDWR);
    if (resfd == -1) {
        printf("Coperd,%s,open %s failed,errno:%d\n", __func__, RESNAME, errno);
        return -1;
    }

    return resfd;
}

static int get_resfd0(void)
{
    if (resfd0 > 0)
        return resfd;

    resfd0 = open(RESNAME0, O_RDWR | O_SYNC);
    if (resfd0 == -1) {
        printf("Coperd,%s,open %s failed,errno:%d\n", __func__, RESNAME0, errno);
        return -1;
    }

    return resfd0;
}

static inline int leap_verify_sp_map()
{
#define LEAP_SP_MAGIC_IDX   (2000)
    const char *magic_str = "QuantumLeap";
    void *sp_db_base = get_sp_db_base();
    char *s = &((char *)sp_db_base)[LEAP_SP_MAGIC_IDX];
    if (strncmp(s, magic_str, strlen(magic_str))) {
        return -1;
    }

    return 0;
}

static int map_res(struct leap *leap)
{
#if defined(__x86_64__)
    int fd, fd0;
    int ret;

    fd = get_resfd();
    assert(fd > 0);

    res_ptr = mmap(0, RES_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (res_ptr == MAP_FAILED) {
        printf("Coperd,%s,resource mapping failed\n", __func__);
        close(fd);
        return -1;
    }
    assert((unsigned long)res_ptr % 4096 == 0);

    fd0 = get_resfd0();
    assert(fd0 > 0);

    res_ptr0 = mmap(0, RES0_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd0, 0);
    if (res_ptr0 == MAP_FAILED) {
        printf("Coperd,%s,resource0 mapping failed\n", __func__);
        munmap(res_ptr, RES0_SZ);
        close(fd);
        close(fd0);
        return -1;
    }
    assert((unsigned long)res_ptr0 % 4096 == 0);

    ret = leap_verify_sp_map();
    if (ret) {
        printf("Coperd, failed to map should-poll page into SoC ..\n");
        exit(EXIT_FAILURE);
    }

    return 0;

#else
    /*
     * For SVK, map kernel NVMe QPs via leap ioctl(), board only supports
     * socp-server now
     */
#ifndef CORE_IOPS_TEST
    if(leap->transport != LEAP_AZURE) {
	    if((leap->role == SOCK_SERVER) ||
	       ((leap->role == SOCK_CLIENT) && (leap->transport == LEAP_PCIE))) {
		    int ret = map_pqps();
		    if (ret) {
			    printf("Coperd,%s,map_pqps() failed\n", __func__);
			    exit(EXIT_FAILURE);
		    }
	    }
    }
#endif

    return 0;

#endif
}

int unmap_res(void)
{
    int fd, fd0;

    int ret = munmap(res_ptr, RES_SZ);
    if (ret == -1) {
        printf("Coperd,%s,munmap resource failed,errno:%d\n", __func__, errno);
        return -1;
    }

    ret = munmap(res_ptr0, RES0_SZ);
    if (ret == -1) {
        printf("Coperd,%s,munmap resource0 failed,errno:%d\n", __func__, errno);
        return -1;
    }

    fd = get_resfd();
    fd0 = get_resfd0();

    if (fd) {
        close(fd);
    }
    if (fd0) {
        close(fd0);
    }

    return 0;
}

static inline void *get_res(void)
{
    return res_ptr;
}

#if defined(__x86_64__)
static void leap_map_host_as(struct leap *leap)
{
    int hfd = open("/dev/mem", O_RDWR);
    if (hfd < 0) {
        printf("Coperd, open \"/dev/mem\" failed ...\n");
        exit(EXIT_FAILURE);
    }

    printf("Coperd,%s,Start mapping host addr space to SOCP ... ", __func__);

#if 0
    leap->host_as_base_va = mmap(0, (1ULL << 37), PROT_READ | PROT_WRITE,
            MAP_PRIVATE, hfd, (1ULL << 39));
#endif
    leap->host_as_base_va = mmap(0, 256ULL << 30, PROT_READ | PROT_WRITE,
            MAP_SHARED, hfd, 256ULL << 30);
    if (leap->host_as_base_va == MAP_FAILED) {
        printf("Coperd,mmap host addr space failed,errno=%d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf(" Done\n");
}
#endif

/* Coperd: host physical memory are mapped to offset:1GB in BAR4 */
static inline void *get_host_phys_addr_base(struct leap *leap)
{
    /* OLD: IVSHMEM based method */
    //return (res_ptr + GB);

    return leap->host_as_base_va;
}

#if 1
/* Coperd: host user 1GB hugepage memory, exposed as IVSHMEM BAR */
static inline void *get_dmabuf_addr_base(struct leap *leap)
{
    void *host_phys_addr_base = get_host_phys_addr_base(leap);

    /* FIXME: only using one 1GB hugepage for now */
    uintptr_t dmabuf = (uintptr_t)host_phys_addr_base + leap->hmr[0].start_hpa;

    return (void *)dmabuf;
}
#else
/* Coperd: host reserved contiguous physical memory, exposed as IVSHMEM BAR */
static inline void *get_dmabuf_addr_base(struct leap *leap)
{
    void *host_phys_addr_base = get_host_phys_addr_base(leap);
    uintptr_t dmabuf = (uintptr_t)host_phys_addr_base + PHY_RSV_DMABUF_BASE;

    return (void *)dmabuf;
}
#endif

/* Coperd: translate host physical addr to socvm socp virtual addr (HPA->GVA) */
/* Coperd: only works after mapping host memory addr space into ivshmem BAR4 */
static uint64_t hpa2va(struct leap *leap, uint64_t hpa)
{
    uint64_t va;
    void *host_phys_addr_base = get_host_phys_addr_base(leap);

    //assert(hpa > 0 && hpa <= RES_SZ);
    va = (uint64_t)((uintptr_t)host_phys_addr_base + hpa);
    assert(va > 0);

    return va;
}

/* Coperd: used by socvm-server for gva->hpa translation in RDMA/TCP cases */
#if 1
/* Coperd: current one, for dmabuf only, using host mapped 1GB hugepage */
static uint64_t va2hpa(struct leap *leap, uint64_t va)
{
    uint64_t oft;
    assert(va >= (uint64_t)leap->dmabuf);

    oft = va - (uint64_t)leap->dmabuf;
    assert(oft <= (2ULL << 30));

    return (leap->dmabuf_hpa + oft);
}
#else
/* Coperd: OLD one, assuming all host memory is mapped into IVSHMEM BAR */
static uint64_t va2hpa(uint64_t va)
{
    void *host_phys_addr_base = get_host_phys_addr_base(leap);
    assert(va >= (uint64_t)host_phys_addr_base);

    return (va - (uint64_t)host_phys_addr_base);
}
#endif

void cleanup(void)
{
    unmap_res();
    close(resfd);
}

static inline unsigned int sq_idx(unsigned int qid, uint32_t stride)
{
    return qid * 2 * stride;
}

static inline unsigned int sq_idx_soc(unsigned int qid, uint32_t stride)
{
    //int half_page = 2048;   // PAGE_SIZE / 2;
    int soc_oft = 256;      // half_page / (2 * sizeof(uint32_t));

    return (qid + soc_oft) * 2 * stride;
}

static inline unsigned int cq_idx(unsigned int qid, uint32_t stride)
{
    return (qid * 2 + 1) * stride;
}

static inline void *get_shadow_db_base(int qid)
{
    void *res_ptr = get_res();

    return (res_ptr + SHADOW_DB_OFT + (qid - 1) * 4096);
}

static inline void *get_sp_db_base()
{
    void *res_ptr = get_res();

    /* Coperd: use the last page for sp_db signal */
    return (res_ptr + RES_QPSZ - 4096);
}

static inline void *get_sp_db(int qid)
{
    void *sp_db_base = get_sp_db_base();

    return &(((uint8_t *)sp_db_base)[qid]);
}

static inline void *get_si_db(int qid)
{
    void *si_db_base = get_sp_db_base() + 2048;

    return &(((uint32_t *)si_db_base)[qid]);
}

static inline void *get_vsq_sdb(int qid)
{
    int stride = 1;
    void *shadow_db_ptr = get_shadow_db_base(qid);
    /* Coperd: we utilize DB written by ATS as the tail */
    int qidx = sq_idx(qid + MAX_NR_VQPS, stride);

    void *vsq_sdb = &((uint32_t *)shadow_db_ptr)[qidx];

    return vsq_sdb;
}

static inline void *get_vsq_sdb_from_ats(int qid)
{
    int stride = 1;

    /* Coperd: we utilize DB written by ATS as the tail */
    /* Coperd: TODO: for now, 1 vQP for each DBVM */
#ifdef MULTI_QP_PER_VHD
    void *shadow_db_ptr = get_shadow_db_base(1);
    int qidx_soc = sq_idx_soc(qid, stride);
#else
    void *shadow_db_ptr = get_shadow_db_base(qid);
    int qidx_soc = sq_idx_soc(1/*qid*/, stride);
#endif

    void *vsq_sdb = &((uint32_t *)shadow_db_ptr)[qidx_soc];

    return vsq_sdb;
}

static inline void *get_vcq_sdb(int qid)
{
    int stride = 1;


#ifdef MULTI_QP_PER_VHD
    void *shadow_db_ptr = get_shadow_db_base(1);
    void *vcq_sdb = &((uint32_t *)shadow_db_ptr)[cq_idx(qid, stride)];
#else
    void *shadow_db_ptr = get_shadow_db_base(qid);
    void *vcq_sdb = &((uint32_t *)shadow_db_ptr)[cq_idx(1/*qid*/, stride)];
#endif

    return vcq_sdb;
}

static inline void *get_vqp_base()
{
    void *res_ptr = get_res();

    return res_ptr + SHADOW_DB_SZ;
}

/* Coperd: assuming fixed queue size of 1024 for now */
static inline void *get_vsq(int sqid)
{
    void *vqp_ptr = get_vqp_base();

    void *vsq = vqp_ptr + VSQ_SZ * (sqid - 1);

    return vsq;
}

static inline void *get_vcq(int cqid)
{
    void *vqp_ptr = get_vqp_base();

    void *vcq = vqp_ptr + MAX_NR_VQPS * VSQ_SZ +  VCQ_SZ * (cqid - 1);

    return vcq;
}

static inline void *get_pres_base()
{
    void *res_ptr = get_res();

    void *pres_base = res_ptr + PRES_OFT;

    return pres_base;
}

static inline void *get_pdb_base()
{
    void *pres_base = get_pres_base();

    return (pres_base + PDB_OFT);
}

static inline int get_psq_db_idx(int qid)
{
    /* Coperd: in host NVMe drive, we create a new set of stealth pQPs */
    return ((1/*NR_HOST_CPUS*/ + 1) * 2 + 2 * (qid - 1));
}

static inline int get_pcq_db_idx(int qid)
{
    return (get_psq_db_idx(qid) + 1);
}

static inline void *get_psq_db(int qid)
{
    int stride = 1;
    void *pdb_ptr = get_pdb_base();

    void *psq_db = &((uint32_t *)pdb_ptr)[sq_idx(qid + 1/*NR_PQP*/, stride)];

    return psq_db;
}

static inline void *get_pcq_db(int qid)
{
    int stride = 1;
    void *pdb_ptr = get_pdb_base();

    void *pcq_db = &((uint32_t *)pdb_ptr)[cq_idx(qid + 1/*NR_PQP*/, stride)];

    return pcq_db;
}

static inline void *get_pqp_base()
{
    void *pres_base = get_pres_base();
    assert(pres_base == res_ptr + PRES_OFT);

    return (pres_base + PSQ_OFT);
}

static inline void *get_psq(int sqid)
{
    void *pqp_ptr = get_pqp_base();

    void *psq = pqp_ptr + PSQ_SZ * (sqid - 1);

    return psq;
}

static inline void *get_pcq_base()
{
    void *pres_base = get_pres_base();
    assert(pres_base == res_ptr + PRES_OFT);

    return (pres_base + PCQ_OFT);
}

static inline void *get_pcq(int cqid)
{
    void *pcq_ptr = get_pcq_base();

    void *pcq = pcq_ptr + PCQ_SZ * (cqid - 1);

    return pcq;
}

void TEST_VSQ(struct nvme_qpair *qps, int nr_qps)
{
    int i, j;
    int sq_tail;

    for (i = 1; i <= 1/*nr_qps*/; i++) {
        struct nvme_qpair *vq = &qps[i];
        //volatile struct nvme_command *tsq = vq->sq_cmds;
        sq_tail = *(vq->sq_db);
        printf("Coperd,=====VSQ[%d]=====, sq_tail=%" PRIu32 "\n", i, sq_tail);
        getchar();
        for (j = 0; j < sq_tail; j++) {
            printf("Coperd,VSQ[%d],%d, ", i, j);
            //print_nvmecmd(&(tsq[j].c));
        }
    }
}

void TEST_VCQ(struct nvme_qpair *qps, int nr_qps)
{
    int i, j;
    int cq_head;

    for (i = 1; i <= 1/*nr_qps*/; i++) {
        struct nvme_qpair *vqp = &qps[i];
        volatile struct nvme_completion *tcq = vqp->cqes;
        cq_head = *(vqp->cq_db);
        printf("Coperd,====VCQ[%d]====, cq_head=%" PRIu32 "\n", i, cq_head);
        getchar();
        for (j = 0; j < cq_head; j++) {
            printf("Coperd,VCQ[%d],%d, ", i, j);
            print_nvmecqe(&(tcq[j]));
        }
    }
}

volatile void *leap_compose_fake_vcmd(volatile struct nvme_command *vcmd)
{
    vcmd->rw.opcode = 0x02; // NVME_CMD_READ
    vcmd->rw.flags = 0;
    vcmd->rw.cid = 0;
    vcmd->rw.nsid = 1;
    vcmd->rw.mptr = 0;
    vcmd->rw.prp1 = 0;
    vcmd->rw.slba = 0;
    vcmd->rw.nlb = 1;
    vcmd->rw.control = 0;

    return vcmd;
}

void leap_test_pqp_initialization(struct nvme_qpair *pqp)
{
    int qid = pqp->qid;
    int i;

    if (qid != 1)
        return;

    // Do some testing here to see if everything is fine ..
    printf("Coperd,%s,sq_cmds=%p\n", __func__, pqp->sq_cmds);
    printf("Coperd,%s,write SQ[%d] db:1,CQ[%d] db:1\n", __func__, qid, qid);
    leap_compose_fake_vcmd(&(pqp->sq_cmds[0]));
    for (i = 0; i < 10; i++) {
        printf("qid[%d,%d]: ", qid, i);
        //print_nvmecmd(&pqp->sq_cmds[i].c);
    }
    printf("Coperd,%s,writing 1 to sq_db\n", __func__);
    *(pqp->sq_db) = (uint32_t)1;
    //*(pqp->cq_db) = (uint32_t)1;
    printf("Coperd,pqp->sq_db=%d,pqp->cq_db=%d\n", *(pqp->sq_db), *(pqp->cq_db));

    sleep(1);
    print_nvmecqe(&(pqp->cqes[0]));
}

/* init qpair fields except queue realted parts */
static void leap_init_qpair_rest(struct nvme_qpair *qpair)
{
    int i;
    struct leap *leap = qpair->leap;
    int dmabuf_idx = 0, rdmabuf_idx = 0;

    assert(leap);
    QTAILQ_INIT(&qpair->req_list);
    QTAILQ_INIT(&qpair->submitter_pending_req_list);
    QTAILQ_INIT(&qpair->completer_pending_req_list);
    QTAILQ_INIT(&qpair->cpl_pending_req_list);

    qpair->cmd_bytes = 0;
    qpair->cur_send_cmd_req = NULL;
    qpair->cur_send_cmd_data_req = NULL;
    qpair->cur_recv_cpl_req = NULL;
    qpair->cur_recv_cpl_data_req = NULL;

    qpair->reqs = (nvme_req *)malloc(sizeof(nvme_req) * VQP_DEPTH);
    assert(qpair->reqs);
    memset(qpair->reqs, 0, sizeof(nvme_req) * VQP_DEPTH);

    dmabuf_idx = (qpair->qid - 1) * VQP_DEPTH;
    rdmabuf_idx = dmabuf_idx * 2;

    for (i = 0; i < VQP_DEPTH; i++) {
        nvme_req *treq = &qpair->reqs[i];
        treq->id = i;
        treq->qp = qpair;

        /* init RDMA related buffer fields (RDMA buffer, SoC <-> SoC) */
        if ((leap->transport == LEAP_RDMA) || (leap->transport == LEAP_STRIPE) ||
                (leap->transport == LEAP_RAID1)) {
            int rbuf_idx = rdmabuf_idx + i * 2;
            int sbuf_idx = rbuf_idx + 1;
            treq->riov = leap->rdma_descs[rbuf_idx].iov;
            treq->riovcnt = leap->rdma_descs[rbuf_idx].max_prps;

            /* we know that treq->riov is virtually continuous */
            treq->rbuf = (void *)treq->riov[0].iov_base;
            treq->rbuflen = treq->riovcnt * leap->pgsz;

            treq->siov = leap->rdma_descs[sbuf_idx].iov;
            treq->siovcnt = leap->rdma_descs[sbuf_idx].max_prps;
            treq->sbuf = (void *)treq->siov[0].iov_base;
            treq->rbuflen = treq->siovcnt * leap->pgsz;
        }

        /* For routing vQP over RDMA */
        /* Layout: CMD|CPL|CMD|CPL|CMD|CPL, each vQP 80KB */
        if ((leap->transport == LEAP_PCIE && leap->use_rdma_for_vqp) ||
	    (leap->transport == LEAP_AZURE && leap->use_rdma_for_vqp) ||
	    (leap->transport == LEAP_TCP && leap->use_rdma_for_vqp)) {
            assert(qpair->qid > 0 && qpair->qid <= NR_DBVMS);
            treq->cmdbuf = (void *)((uintptr_t)leap->nvme_qpair_buf + (qpair->qid - 1) * RBUF_SIZE * 1024
				    + RBUF_SIZE * i);
            treq->cplbuf = (void *)((uintptr_t)treq->cmdbuf + NVME_CMD_SZ);
        }

        /* DMA buffer for server (SoC <-> SSD) */
        if (leap->role == SOCK_SERVER ||
	    (leap->transport == LEAP_PCIE && leap->use_rdma_for_vqp) ||
	    (leap->transport == LEAP_AZURE && leap->use_rdma_for_vqp) ||
	    (leap->transport == LEAP_TCP && leap->use_rdma_for_vqp)) {
		treq->iov = leap->dma_descs[dmabuf_idx + i].iov;
		/* iovcnt later will be set correctly according to cmd data size */
		treq->iovcnt = leap->dma_descs[dmabuf_idx + i].max_prps;
		assert(treq->iov);
        }
        QTAILQ_INSERT_TAIL(&qpair->req_list, treq, entry);
        treq->status = IN_REQ_LIST;
    }

#if defined(__x86_64__)
    qpair->s2c_rq = femu_ring_create(FEMU_RING_TYPE_MP_SC, VQP_DEPTH);
    assert(qpair->s2c_rq);
    assert(rte_ring_empty(qpair->s2c_rq));

    qpair->c2s_rq = femu_ring_create(FEMU_RING_TYPE_MP_SC, VQP_DEPTH);
    assert(qpair->c2s_rq);
    assert(rte_ring_empty(qpair->c2s_rq));
#else
    QTAILQ_INIT(&qpair->s2c_list);
    QTAILQ_INIT(&qpair->c2s_list);
    assert(QTAILQ_EMPTY(&qpair->s2c_list));
    assert(QTAILQ_EMPTY(&qpair->c2s_list));
#endif

    if(leap->role == SOCK_CLIENT || leap->role == SOCK_SERVER) {
	    qpair->role = leap->role;

	    if (qpair->qid * 2 <= leap->nfds) {
		    qpair->cmd_sockfd = leap->sockfds[(qpair->qid - 1) * 2];
		    qpair->data_sockfd = leap->sockfds[(qpair->qid - 1) * 2 + 1];
	    } else {
		    printf("Coperd,IGNORE DBVM[%d] TCP connections..\n", qpair->qid);
	    }
    } else {
	    qpair->role = SOCK_AZURE;
	    qpair->m_drive = leap->m_azure_drive;
    }
}

int leap_init_pqp(struct leap *leap, struct nvme_qpair *pqp, int qid)
{
#if defined(__x86_64__)
    assert(pqp != NULL);

    memset(pqp, 0, sizeof(*pqp));

    pqp->leap = leap;
    pqp->qid = qid;
    pqp->q_depth = 1024;
    pqp->sq_tail = 0;
    pqp->cq_head = 0;
    pqp->sq_head = 0;
    pqp->cq_tail = 0;
    pqp->sq_cmds = (volatile struct nvme_command *)get_psq(pqp->qid);
    pqp->cqes = (volatile struct nvme_completion *)get_pcq(pqp->qid);
    //pqp->sq_db = (uint32_t *)get_psq_db(pqp->qid);
    //pqp->cq_db = (uint32_t *)get_pcq_db(pqp->qid);
    //pqp->sq_db = &((uint32_t *)(res_ptr0 + 18))[qid - 1];
    //pqp->cq_db = &((uint32_t *)(res_ptr0 + 18))[qid];
    pqp->sq_db = &((uint32_t *)(res_ptr0))[get_psq_db_idx(qid)];
    pqp->cq_db = &((uint32_t *)(res_ptr0))[get_pcq_db_idx(qid)];
    pqp->cq_phase = 1;

    leap_init_qpair_rest(pqp);

#ifdef FDEBUG
    leap_test_pqp_initialization(pqp);
#endif

    return 0;

#else
    assert(pqp != NULL);

    memset(pqp, 0, sizeof(*pqp));

    pqp->leap = leap;
    pqp->qid = qid;
    pqp->q_depth = 1024;
    pqp->sq_tail = 0;
    pqp->cq_head = 0;
    pqp->sq_head = 0;
    pqp->cq_tail = 0;
    //assert(qpbuf_socp[qid].qid == pqp->qid);
#ifndef CORE_IOPS_TEST
    //assert(qpbuf_socp[qid].q_depth == pqp->q_depth);
#endif
    pqp->sq_cmds = (volatile struct nvme_command *)qpbuf_socp[qid].sqbuf;
    pqp->cqes = (volatile struct nvme_completion *)qpbuf_socp[qid].cqbuf;
    //pqp->sq_db = (uint32_t *)get_psq_db(pqp->qid);
    //pqp->cq_db = (uint32_t *)get_pcq_db(pqp->qid);
    //pqp->sq_db = &((uint32_t *)(res_ptr0 + 18))[qid - 1];
    //pqp->cq_db = &((uint32_t *)(res_ptr0 + 18))[qid];
    pqp->sq_db = qpbuf_socp[qid].sqdb;
    pqp->cq_db = qpbuf_socp[qid].cqdb;
    pqp->cq_phase = 1;

    debug("finished assigning pqp bufs and dbells\n");

    leap_init_qpair_rest(pqp);

    /* Associate NVMe vQP with RDMA QP context */
    if ((leap->transport == LEAP_PCIE && leap->use_rdma_for_vqp) ||
	(leap->transport == LEAP_AZURE && leap->use_rdma_for_vqp) ||
	(leap->transport == LEAP_TCP && leap->use_rdma_for_vqp)){
        pqp->rctx = &leap->rctx2[pqp->qid - 1];
        assert(pqp->rctx);
        printf("QP-PCIe: pqp[%d].rctx=%p\n", pqp->qid, pqp->rctx);
    }


#ifdef FDEBUG
    leap_test_pqp_initialization(pqp);
#endif

    return 0;

#endif
}

int leap_init_pqps(struct leap *leap)
{
    int i;
    struct nvme_qpair *pqps = leap->pqps;
    struct nvme_qpair *pqp;

    /* Coperd: resize the qid */
    for (i = 1; i <= NR_DBVMS/*leap->nr_pqps*/; i++) {
        pqp = &pqps[i];
        leap_init_pqp(leap, pqp, i);
    }

    return 0;
}

int leap_init_pqps_stripe(struct leap *leap)
{
    int i;
    struct nvme_qpair *pqps = leap->pqps;
    struct nvme_qpair *pqp;

    /* Coperd: resize the qid */
    for (i = NR_DBVMS + 1; i <= NR_DBVMS + NR_DBVMS/*leap->nr_pqps*/; i++) {
        pqp = &pqps[i];
        leap_init_pqp(leap, pqp, i);
    }

    return 0;
}

/* Coperd: mock the controller */
int leap_init_vqp(struct leap *leap, struct nvme_qpair *vqp, int qid)
{
    assert(vqp != NULL);
    pthread_mutex_init(&vqp->lock, NULL);

    memset(vqp, 0, sizeof(*vqp));

    vqp->leap = leap;
    vqp->qid = qid;
    vqp->q_depth = VQP_DEPTH;
    vqp->sq_cmds = (struct nvme_command *)get_vsq(vqp->qid);
    vqp->cqes = (struct nvme_completion *)get_vcq(vqp->qid);
    vqp->sq_db = (uint32_t *)get_vsq_sdb_from_ats(vqp->qid);
    printf("Coperd,%s,qid=%d,vqp->sq_db=%p\n", __func__, qid, vqp->sq_db);
    //vqp->sp_db = vqp->sq_db + 1;
    vqp->sp_db = (volatile uint8_t *)get_sp_db(vqp->qid);
    printf("Coperd,%s,qid=%d,vqp->sp_db=%p\n", __func__, qid, vqp->sp_db);
    vqp->si_db = (volatile uint32_t *)get_si_db(vqp->qid);
    vqp->cq_db = (uint32_t *)get_vcq_sdb(vqp->qid);
    vqp->sq_tail = 0; //*(vqp->sq_db);
    vqp->cq_head = 0; //*(vqp->cq_db);
    vqp->sq_head = 0;
    vqp->cq_tail = 0;
    /* Coperd: controller side Phase Tag is initialized to 1 */
    vqp->cq_phase = 1;

#if 0
    *(vqp->sp_db) = 0;
    *(vqp->si_db) = 0;
    *(vqp->sq_db) = 0;
    *(vqp->cq_db) = 0;
#endif

    leap_init_qpair_rest(vqp);

    return 0;
}

int leap_reinit_vqp(struct nvme_qpair *vqp)
{
    /* Coperd: TODO: need to read this information from DBVM */
    vqp->q_depth = VQP_DEPTH;
    /* Coperd: all the DB and vSQ/vCQ virtual addr don't change */

    /* Coperd: we only need to reinit the counters about the vQP */
    vqp->sq_tail = 0;
    vqp->sq_head = 0;
    vqp->cq_head = 0;
    vqp->cq_tail = 0;
    vqp->cq_phase = 1;

    return 0;
}

int leap_init_vqps(struct leap *leap)
{
    struct nvme_qpair *vqps = leap->vqps;
    struct nvme_qpair *vqp;
    int i;

    /* Coperd: vQPs */
    for (i = 1; i <= NR_DBVMS; i++) {
        vqp = &vqps[i];
        leap_init_vqp(leap, vqp, i);
    }

    return 0;
}

bool vsq_empty(struct nvme_qpair *vqp)
{
    //printf("Coperd,%s,sq_tail=%d\n", __func__, vqp->sq_tail);
    return (vqp->sq_head == vqp->sq_tail);
}

static uint64_t empty_cnt = 0;

void vsq_update_tail(struct nvme_qpair *vqp)
{
    assert(vqp);
    assert(vqp->sq_db);

    //printf("Coperd,%s,soc_db=%p\n", __func__, vqp->sq_db);
    uint16_t tail = *(vqp->sq_db);

#ifdef DEBUG_VQP
    if (tail != vqp->sq_tail) {
        printf("Coperd,vqp[%d],new tail:%d,old:%d\n", vqp->qid, tail,vqp->sq_tail);
    }
#endif

    if (!(tail >= 0 && tail < vqp->q_depth)) {
        empty_cnt++;
#ifdef DEBUG_VQP
        if (empty_cnt % 100000 == 0) {
            printf("Coperd,%s,empty_cnt=%ld\n", __func__, empty_cnt);
        }
#endif
        return;
    }

    vqp->sq_tail = tail;
}

void inline vsq_inc_head(struct nvme_qpair *vqp)
{
    vqp->sq_head = (vqp->sq_head + 1) % vqp->q_depth;
}

struct nvme_qpair *vqp_get_mapping_pqp(struct leap *leap, struct nvme_qpair *vqp)
{
    struct nvme_qpair *pqps = leap->pqps;
    /* Coperd: only support naive 1-to-1 map for now; TODO */
    struct nvme_qpair *pq = &pqps[vqp->qid];

    return pq;
}

static inline void leap_ring_psq_doorbell(struct nvme_qpair *pqp, uint16_t tail)
{
    leap_wmb();
    leap_mmio_write_4(pqp->sq_db, tail);
}

void leap_write_cmd_to_psq(struct nvme_qpair *pqp, struct nvme_command *pcmd)
{
    uint16_t tail = pqp->sq_tail;

#ifdef DEBUG_PQP
    printf("Coperd,%s,%d,pSQ[%d],%d, ", __func__, __LINE__, pqp->qid,
            pqp->sq_tail);
    print_nvmecmd(pcmd);
#endif

    memcpy((void *)&pqp->sq_cmds[pqp->sq_tail], pcmd, sizeof(*pcmd));

    if (++tail == pqp->q_depth) {
        tail = 0;
    }

    pqp->sq_tail = tail;
}

void leap_submit_pcmd(struct nvme_qpair *pqp, struct nvme_command *pcmd)
{
    //uint16_t tail = pqp->sq_tail;

    leap_write_cmd_to_psq(pqp, pcmd);

    /* Coperd: ring the doorbell */
    leap_ring_psq_doorbell(pqp, pqp->sq_tail);
}

int vcq_inc_tail(struct nvme_qpair *vqp)
{
    vqp->cq_tail++;
    if (vqp->cq_tail >= vqp->q_depth) {
        vqp->cq_tail = 0;
        vqp->cq_phase = !vqp->cq_phase;
    }

    return 0;
}

static uint64_t gpg = 0;
static uint64_t gblk = 0;

uint64_t leap_addr_lba2dev(uint64_t spba)
{
    uint8_t ch_off = 26;
    uint8_t lun_off = 23;
    uint8_t pl_off = 2;
    uint8_t blk_off = 12;
    uint8_t pg_off = 4;
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

void *leap_vcmd_to_oc_pcmd(struct nvme_command *vcmd)
{
    struct nvme_command *pcmd;

    /* Coperd: modify the cmd in place since no one else is accessing it */
    pcmd = vcmd;

    pcmd->ocrw.opcode = NVM_OP_PREAD;
    pcmd->ocrw.nsid = cpu_to_le32(1);
    pcmd->ocrw.spba = cpu_to_le64(leap_addr_lba2dev(vcmd->ocrw.spba));
    /* dma_meta_list */
    pcmd->ocrw.metadata = cpu_to_le64(0);
    /* flags */
    pcmd->ocrw.control = cpu_to_le16(NVM_IO_SUSPEND | NVM_IO_SCRAMBLE_ENABLE);
    pcmd->ocrw.length = cpu_to_le16(0); /* nr_ppas - 1 */

    return pcmd;
}

void *leap_vcmd_to_nvme_pcmd(struct nvme_command *vcmd)
{
#if 0
    vcmd->rw.nlb = cpu_to_le16(((le16_to_cpu(vcmd->rw.nlb) + 1) << 3) - 1);
    vcmd->rw.slba = cpu_to_le64(le64_to_cpu(vcmd->rw.slba) << 3);
#endif
    return vcmd;
}

void *leap_vcmd_to_pcmd(struct nvme_command *vcmd)
{
    return leap_vcmd_to_nvme_pcmd(vcmd);
    //return leap_vcmd_to_oc_pcmd(vcmd);
}

/* Coperd: TODO TODO */
void leap_post_vcqe(struct nvme_qpair *vqp, uint16_t status, int cid)
{
    uint8_t phase = vqp->cq_phase;
    struct nvme_completion cqe;

    cqe.status = cpu_to_le16((status << 1) | phase);
    cqe.sq_id = cpu_to_le16(vqp->qid);
    cqe.sq_head = cpu_to_le16(vqp->sq_head);
    cqe.cid = cpu_to_le16(cid);

    memcpy((void *)&vqp->cqes[vqp->cq_tail], &cqe, sizeof(cqe));

    vcq_inc_tail(vqp);
}

bool leap_vcmd_reg_rw_valid(struct nvme_command *vcmd)
{
    struct nvme_rw_command *rw = &(vcmd->rw);
    uint8_t opc = rw->opcode;

    if (opc == NVME_CMD_FLUSH || opc == NVME_CMD_WRITE || opc == NVME_CMD_READ)
        return true;

    return false;
}

bool leap_vcmd_oc_rw_valid(struct nvme_command *vcmd)
{
    struct nvme_oc_rw *ocrw = &(vcmd->ocrw);
    uint8_t opc = ocrw->opcode;

    if (opc == NVM_OP_PREAD || opc == NVM_OP_PWRITE || opc == NVM_OP_ERASE)
        return true;

    return false;
}

bool leap_vcmd_valid(struct nvme_command *vcmd)
{
    struct nvme_rw_command *rw = &(vcmd->rw);

    uint32_t nsid = le32_to_cpu(rw->nsid);
    //uint32_t nlb = le32_to_cpu(rw->nlb) + 1;
    //uint64_t slba = le64_to_cpu(rw->slba);

    if (nsid != 1)
        return false;

    if (!leap_vcmd_reg_rw_valid(vcmd) && !leap_vcmd_oc_rw_valid(vcmd))
        return false;

#if 0
    if (slba + nlb > 0x100000000000000) {
        return NVME_LBA_RANGE | NVME_DNR;
    }
#endif

    /* Coperd: more illeagle cases later, TODO */

    return true;
}

static inline uint8_t vqp_get_sp(struct nvme_qpair *vqp)
{
    uint8_t spv = *(vqp->sp_db);
    return spv;
}

static inline void vqp_inc_si(struct nvme_qpair *vqp)
{
    uint32_t prev_si = *(vqp->si_db);
    *(vqp->si_db) = (prev_si + 1) % UINT32_MAX;
}

static inline bool vqp_disabled(struct nvme_qpair *vqp, uint8_t cur_spv)
{
    return (vqp->prev_spv == 1) && (cur_spv == 0);
}

/* Coperd: translate HPAs in command prp list into socp VA */
static bool client_map_prps_to_iov(nvme_req *req)
{
    struct leap *leap = req->qp->leap;
    struct nvme_command *cmd = &req->cmd;
    uint8_t opc = cmd->c.opcode;
    uint64_t prp1 = le64_to_cpu(cmd->c.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->c.prp2);
    uint16_t nlb = le16_to_cpu(cmd->rw.nlb) + 1;
    /* DATA_SHIFT represents power of logical block size */
    int len = nlb << DATA_SHIFT;
    int data_len = len;
    //int nprps = 0;
    //int cmax_prps = MDTS / 512 + 1;
    uint64_t prp1_va, prp2_va;

    /* Coperd: usually the controller page size is 4KB, TODO */
    int cpgsz = 4096;
    int cpgbits = 12;
    int max_prp_ents = 512; /* cpgsz / sizeof(uint64_t) */
    int trans_len = cpgsz - (prp1 % cpgsz);
    int num_prps = (len >> cpgbits) + 1;

    uint64_t *prp_list;
    int i = 0;

    struct iovec *req_iov;
    int iovcnt = 0;

    /* Coperd: erase cmd doesn't carry prps */
    if (opc == NVM_OP_ERASE) {
        req->len = 0;
        req->iov = NULL;
        req->iovcnt = 0;
        return true;
    }

    if (opc == NVM_OP_PREAD || opc == NVM_OP_PWRITE) {
        printf("Coperd,%s,OCSSD read/write not supported yet ..\n", __func__);
    }

    /* Coperd: TODO: at most num_prps buffers ???? */
    req_iov = (struct iovec *)malloc(sizeof(struct iovec) * num_prps);
    assert(req_iov);
    memset(req_iov, 0, sizeof(struct iovec) * num_prps);

    trans_len = min(len, trans_len);

    if (!prp1) {
        printf("Coperd,%s,prp1=0\n", __func__);
        goto err;
    }

    prp1_va = hpa2va(leap, le64_to_cpu(prp1));
    len -= trans_len;

    iovcnt++;
    req_iov[0].iov_base = (void *)prp1_va;
    req_iov[0].iov_len = trans_len;
    assert(iovcnt == 1);
    //printf("Coperd,%s,req[%d],iov[%d]:(0x%lx,%ld)\n", __func__, req->id, iovcnt-1, (uintptr_t)req_iov[iovcnt-1].iov_base, req_iov[iovcnt-1].iov_len);

    /* only 1 prp entry in the command, we are done here */
    if (!len) {
        goto end;
    }

    if (!prp2) {
        printf("Coperd,%s,%d,error\n", __func__, __LINE__);
        goto err;
    }

    prp2_va = hpa2va(leap, le64_to_cpu(prp2));
    iovcnt++;

    /* Coperd: only 2 prp entries, only need to add prp2 to iov */
    if (len <= cpgsz) {
        if (prp2 & (cpgsz - 1)) {
            /* this shouldn't happen */
            printf("Coperd,%s,%d,error,prp2=0x%lx\n", __func__, __LINE__, prp2);
            goto err;
        }

        /* done */
        assert(iovcnt == 2);
        req_iov[1].iov_base = (void *)prp2_va;
        req_iov[1].iov_len = len;
        //printf("Coperd,%s,req[%d],iov[%d]:(0x%lx,%ld)\n", __func__, req->id, iovcnt-1, (uintptr_t)req_iov[iovcnt-1].iov_base, req_iov[iovcnt-1].iov_len);
        goto end;
    }

    /* Coperd: handle >=3 prp in the command */
    iovcnt--;
    prp_list = (uint64_t *)prp2_va;
    while (len != 0) {
        uint64_t prp_ent = le64_to_cpu(prp_list[i]);
        uint64_t vaddr;

        /* Coperd: last ent in prp_list is a pointer to another prp list page */
        if (i == max_prp_ents - 1 && len > cpgsz) {
            if (!prp_ent || prp_ent & (cpgsz - 1)) {
                printf("Coperd,secondary prp page\n");
                goto err;
            }
            i = 0;

            uint64_t prp_va = hpa2va(leap, prp_ent);
            prp_list = (uint64_t *)prp_va;
            prp_ent = le64_to_cpu(prp_list[i]);
        }

        if (!prp_ent || prp_ent & (cpgsz - 1)) {
            printf("Coperd,%s,%d,error,prp_ent[%d]=0x%lx\n", __func__, __LINE__,
                    i, prp_ent);
            //goto err;

            /* TODO: hack to not to fail socp upon ATS errors */
            prp_ent = 11ULL * 1024 * 1024 * 1024;
        }

        trans_len = min(len, cpgsz);
        vaddr = hpa2va(leap, prp_ent);
        iovcnt++;
        req_iov[iovcnt-1].iov_base = (void *)vaddr;
        req_iov[iovcnt-1].iov_len = trans_len;
        //printf("Coperd,%s,req[%d],iov[%d]:(0x%lx,%ld)\n", __func__, req->id, iovcnt-1, (uintptr_t)req_iov[iovcnt-1].iov_base, req_iov[iovcnt-1].iov_len);

        len -= trans_len;
        i++;
    }

end:
    /* Coperd: this is the result we want to get */
    req->len = data_len;
    req->iov = req_iov;
    req->iovcnt = iovcnt;
    assert(iovcnt <= num_prps);
    assert(req->iov && req->len > 0 && req->iovcnt > 0);
    return true;

err:
    free(req_iov);
    req->len = 0;
    req->iov = NULL;
    req->iovcnt = 0;
    return false;
}

#define MAX_BATCH_SZ        (8)
#define MAX_RDMA_BATCH_SZ   (16)

/*
 * @type: 0 for cmd and 1 for cpl
 */
static inline void save_cid(nvme_req *req, int type)
{
#ifdef USE_LEAP_CID
    struct nvme_command *cmd = &req->cmd;
    struct nvme_completion *cpl = &req->cpl;

    if (type == 0) {
        /* cmd */
        req->cid = cmd->c.cid;
        cmd->c.cid = req->id;
        printf("Coperd,%s,save cmd cid[%d]->%d\n", __func__, req->cid, req->id);
    } else if (type == 1) {
        req->cid = cpl->cid;
        cpl->cid = req->id;
        printf("Coperd,%s,save cpl cid[%d]->%d\n", __func__, req->cid, req->id);
    } else {
        assert(0);
    }
#endif
}

static inline void restore_cid(nvme_req *req, int type)
{
#ifdef USE_LEAP_CID
    struct nvme_command *cmd = &req->cmd;
    struct nvme_completion *cpl = &req->cpl;

    if (type == 0) {
        /* cmd */
        cmd->c.cid = req->cid;
    } else if (type == 1) {
        /* cpl */
        cpl->cid = req->cid;
    } else {
        assert(0);
    }
#endif
}

/* Coperd: we use lower 4 bits in cmd->nsid to store vqp->qid */
/* NOT USED NOW */
#define VQP_QID_BITS (4)

static void save_qid_in_cmd(nvme_req *req)
{
#ifdef USE_CMD_FOR_QID
    struct nvme_command *cmd = &req->cmd;
    uint32_t new_nsid;

    new_nsid = (le32_to_cpu(cmd->c.nsid) << VQP_QID_BITS) | req->qp->qid;

    cmd->c.nsid = cpu_to_le32(new_nsid);
#endif
}

static void client_parse_cmd(nvme_req *req)
{
    bool r;
    struct nvme_command *cmd = &req->cmd;
    int opc = cmd->c.opcode;

    /*
     * For LocalSSD with vQP routed via RDMA, socp is actually accessing
     * physicla SSD directly, thus, when we prepare the req, prp should be
     * filled with SoC HPA from its own DMABUF
     */
#if 0
#if !defined(__x86_64__)
    if (req->qp->leap->use_rdma_for_vqp) {
        server_prep_cmd(req->qp, req);
        return;
    }
#endif
#endif

    /* Save cid from guest */
    save_cid(req, 0);

    save_qid_in_cmd(req);

    req->is_write = false;
    if (opc == NVME_CMD_WRITE || opc == NVM_OP_PWRITE) {
        req->is_write = true;
    }

    /* Construct iov from cmd prp list, update req ->len, ->iovcnt, ->iov */
    if (!req->qp->leap->use_rdma_for_vqp) {
        r = client_map_prps_to_iov(req);
        if (!r) {
            printf("Coperd,prps_to_iov failed\n");
            abort();
        }
    }
}

static inline int get_req_data_len(struct nvme_command *cmd)
{
    uint16_t nlb;
    int len;

    nlb = le16_to_cpu(cmd->rw.nlb) + 1;
    /* TODO TODO TODO */
    len = nlb << DATA_SHIFT;

    return len;
}

static inline bool server_allocate_iov(struct nvme_qpair *pqp, nvme_req *req)
{
    /* TODO: in future, we should have a general memory allocator for this */
    /* Currently, req->iov is initialized during leap init phase */
    return true;
}

#if 1
inline bool is_valid_prp(uint64_t prp)
{
    /* FIXME: using hugepage buffer for dmabuf, skip prp checking */
    return true;
}
#else
inline bool is_valid_prp(uint64_t prp)
{
    return prp >= PHY_RSV_DMABUF_BASE && prp <= PHY_RSV_DMABUF_END;
}
#endif

double hpa_bytes_to_gb(uint64_t hpa)
{
    return (double)hpa / 1024 / 1024 / 1024;
}

/* Fill cmd prp list according req->iov info for DMA */
bool server_setup_prps_from_iov(struct nvme_qpair *pqp, nvme_req *req)
{
    struct leap *leap = pqp->leap;
    struct nvme_command *cmd = &req->cmd;
    int len = req->len;
    uint64_t *prp2_va;
    int iov_idx, prp_idx;
    int pgsz = leap->pgsz;
    //int max_prps_in_pg = pgsz / sizeof(uint64_t);
    int cnt = 0;

    assert(req->iov);
    /* buffer always starts at page boundary, thus we can use len to decide how
     * many prps are needed to represent the overall DMA buffers */
    if (len <= pgsz) {
        /* only prp1 is needed */
        cmd->c.prp1 = cpu_to_le64(va2hpa(leap, (uint64_t)req->iov[0].iov_base));
#ifdef DEBUG_PQP
        printf("Coperd,%s,pqp[%d],prp1=%.6f GB\n", __func__, pqp->qid,
                hpa_bytes_to_gb(cmd->c.prp1));
#endif
        assert(is_valid_prp(cmd->c.prp1));
        cmd->c.prp2 = 0;
        req->iovcnt = 1;
        return true;
    } else if (len <= pgsz * 2) {
        /* only 2 prps needed */
        cmd->c.prp1 = cpu_to_le64(va2hpa(leap, (uint64_t)req->iov[0].iov_base));
        cmd->c.prp2 = cpu_to_le64(va2hpa(leap, (uint64_t)req->iov[1].iov_base));
#ifdef DEBUG_PQP
        printf("Coperd,%s,pqp[%d],prp1=%.6f GB, prp2=%.6f GB\n", __func__, pqp->qid,
                hpa_bytes_to_gb(cmd->c.prp1), hpa_bytes_to_gb(cmd->c.prp2));
#endif
        assert(is_valid_prp(cmd->c.prp1));
        assert(is_valid_prp(cmd->c.prp2));
        req->iovcnt = 2;
        return true;
    }

    /* >= 3 prps needed */
    /* TODO: only assuming one prp meta page is enough, i.e., <= 512 prps */
    cmd->c.prp1 = cpu_to_le64(va2hpa(leap, (uint64_t)req->iov[0].iov_base));
    len -= pgsz;
#ifdef DEBUG_PQP
    printf("Coperd,%s,pqp[%d], prp1=%.6f GB\n", __func__, pqp->qid,
            hpa_bytes_to_gb(cmd->c.prp1));
#endif
    assert(is_valid_prp(cmd->c.prp1));
    /* req->iov[MAX_PRPS] is reseved for storing prp_list addr */
    cmd->c.prp2 = cpu_to_le64(va2hpa(leap, (uint64_t)req->iov[MAX_PRPS].iov_base));
    prp2_va = (uint64_t *)req->iov[MAX_PRPS].iov_base;
#ifdef DEBUG_PQP
    printf("Coperd,%s,pqp[%d],prp2=%.6f GB\n", __func__, pqp->qid,
            hpa_bytes_to_gb(cmd->c.prp2));
#endif
    assert(is_valid_prp(cmd->c.prp2));

    iov_idx = 1;
    prp_idx = 0;
    cnt = 1;
    while (len >= pgsz) {
        prp2_va[prp_idx] = cpu_to_le64(va2hpa(leap, (uint64_t)req->iov[iov_idx].iov_base));
#ifdef DEBUG_PQP
        printf("Coperd,%s,pqp[%d],prp2[%d]=%.6f GB\n", __func__, pqp->qid, prp_idx,
                hpa_bytes_to_gb(prp2_va[prp_idx]));
#endif
        assert(is_valid_prp(prp2_va[prp_idx]));
        len -= pgsz;
        iov_idx++;
        prp_idx++;
        cnt++;
    }
    if (len > 0) {
        prp2_va[prp_idx] = cpu_to_le64(va2hpa(leap, (uint64_t)req->iov[iov_idx].iov_base));
#ifdef DEBUG_PQP
        printf("Coperd,%s,pqp[%d],prp2[%d]=%.6f GB\n", __func__, pqp->qid, prp_idx,
                hpa_bytes_to_gb(prp2_va[prp_idx]));
#endif
        assert(is_valid_prp(prp2_va[prp_idx]));
        req->iov[iov_idx].iov_len = len;
        cnt++;
    }
    /* TODO: TOFIX in future, make sure they fit into one prp meta page */
    assert(prp_idx <= MAX_PRPS);
    assert(cnt >= 3);
    req->iovcnt = cnt;
#ifdef DEBUG_PQP
    printf("Coperd,%s,req->iovcnt=%d\n", __func__, req->iovcnt);
#endif

    return true;
}

#if 0
static void print_req(nvme_req *req) {
    printf("Coperd,req[%d],cmd.cid:%d,iovcnt:%d,cmd_bytes:%d,data_bytes:%d,"
            "cpl.cid:%d,len:%d,cur_iov_idx:%d,cur_iov_oft:%d\n",
            req->id, req->cmd.c.cid, req->iovcnt, req->cmd_bytes,
            req->data_bytes, req->cpl.cid, req->len, req->cur_iov_idx,
            req->cur_iov_oft);
}
#endif

static void server_prep_cmd(struct nvme_qpair *pqp, nvme_req *req)
{
    struct nvme_command *cmd = &req->cmd;
    int opc = cmd->c.opcode;
    int rc;

    /* Save cid from client */
    save_cid(req, 0);

    req->is_write = false;
    if (opc == NVME_CMD_WRITE || opc == NVM_OP_PWRITE) {
        req->is_write = true;
    }

    req->len = get_req_data_len(cmd);

    rc = server_allocate_iov(pqp, req);
    assert(rc);

    // TODO: before setup prp, iov should already be filled by recving data
    // TODO TODO TODO
    rc = server_setup_prps_from_iov(pqp, req);
    if (!rc) {
        printf("Coperd,%s,error,rc=%d\n", __func__, rc);
    }

#if 0
    printf("after serv_prep_cmd: ");
    print_req(req);
#endif
}

/*
 * nvme_req exchange between submitter and completer
 * For submitter: drain ->c2s_rq and insert them to ->req_list
 * For completer: drain ->s2c_rq and insert them to ->completer_pending_req_list
 */
static void drain_rq(struct nvme_qpair *qp, bool is_submitter)
{
#if defined(__x86_64__)
    nvme_req *req;
    struct rte_ring *rq;

    if (is_submitter) {
        rq = qp->c2s_rq;
    } else {
        rq = qp->s2c_rq;
    }

    while (femu_ring_dequeue(rq, (void **)&req, 1) == 1) {
        assert(req == &qp->reqs[req->id]);
        if (is_submitter) {
            //assert(req->status == IN_COMPLETER_P_LIST);
            QTAILQ_INSERT_TAIL(&qp->req_list, req, entry);
            req->status = IN_REQ_LIST;

#ifdef DEBUG_RTE_RING
            printf("Coperd,%s,qp[%d],insert req[%d] to req_list\n", __func__,
                    qp->qid, req->id);
#endif
        } else {
		assert(req->status == IN_SUBMITTER_P_LIST);
            QTAILQ_INSERT_TAIL(&qp->completer_pending_req_list, req, entry);
            req->status = IN_COMPLETER_P_LIST;
#ifdef DEBUG_RTE_RING
            printf("Coperd,%s,qp[%d],insert req[%d] to completer_pending_req_list\n",
                    __func__, qp->qid, req->id);
#endif
        }
    }

#else
    nvme_req *req;

    if (is_submitter) {
        //rq = qp->c2s_rq;
    } else {
        //rq = qp->s2c_rq;
    }

    if (is_submitter) {
        while (!QTAILQ_EMPTY(&qp->c2s_list)) {
            req = QTAILQ_FIRST(&qp->c2s_list);
            assert(req == &qp->reqs[req->id]);
            //assert(req->status == IN_COMPLETER_P_LIST);
            QTAILQ_REMOVE(&qp->c2s_list, req, entry);
            QTAILQ_INSERT_TAIL(&qp->req_list, req, entry);
            req->status = IN_REQ_LIST;

#ifdef DEBUG_RTE_RING
            printf("Coperd,%s,qp[%d],insert req[%d] to req_list\n", __func__,
                    qp->qid, req->id);
#endif
        }
    } else {
        /* TODO */
        while (!QTAILQ_EMPTY(&qp->s2c_list)) {
            req = QTAILQ_FIRST(&qp->s2c_list);
            assert(req == &qp->reqs[req->id]);
            assert(req->status == IN_SUBMITTER_P_LIST);
            QTAILQ_REMOVE(&qp->s2c_list, req, entry);
            QTAILQ_INSERT_TAIL(&qp->completer_pending_req_list, req, entry);
            req->status = IN_COMPLETER_P_LIST;
#ifdef DEBUG_RTE_RING
            printf("Coperd,%s,qp[%d],insert req[%d] to completer_pending_req_list\n",
                    __func__, qp->qid, req->id);
#endif
        }
    }

#endif
}

#if 0
static void drain_rq_until(struct nvme_qpair *qp, bool is_submitter,
        nvme_req *tgt_req)
{
    nvme_req *req;
    struct rte_ring *rq;

    if (is_submitter) {
        rq = qp->c2s_rq;
    } else {
        rq = qp->s2c_rq;
    }

    while (femu_ring_dequeue(rq, (void **)&req, 1) == 1) {
        assert(req == &qp->reqs[req->id]);
        if (is_submitter) {
            QTAILQ_INSERT_TAIL(&qp->req_list, req, entry);
            req->status = IN_REQ_LIST;
#ifdef DEBUG_RTE_RING
            printf("Coperd,%s,qp[%d],insert req[%d] to req_list\n", __func__,
                    qp->qid, req->id);
#endif
        } else {
            QTAILQ_INSERT_TAIL(&qp->completer_pending_req_list, req, entry);
            req->status = IN_COMPLETER_P_LIST;
#ifdef DEBUG_RTE_RING
            printf("Coperd,%s,qp[%d],insert req[%d] to completer_pending_req_list\n",
                    __func__, qp->qid, req->id);
#endif
        }

        if (req == tgt_req) {
            return;
        }
    }
}
#endif

/*
 * advance ->cur_iov_idx and ->cur_iov_oft accordingly after some success reads
 * cur_iov represents the iovec state after some successful transfer
 * make sure ->iov[] base and len are not changed
 */
void advance_req_iov_status(nvme_req *req, struct iovec *req_iov, int len)
{
    int i = 0;
    unsigned bytes;

    /* ZERO data transfer last time (EWOULDBLOCK | EAGAIN) */
    if (len == 0) {
        return;
    }

    req->data_bytes += len;
    assert(req->data_bytes <= req->len);

    bytes = req->data_bytes;
    req->cur_iov_idx = 0;
    req->cur_iov_oft = 0;
    /* advance req->iov status */
    while (bytes > req_iov[i].iov_len) {
        /* advance iov by one */
        bytes -= req_iov[i].iov_len;
        req->cur_iov_idx++;
        i++;
    }

    assert(bytes >= 0);
    if (bytes == req_iov[i].iov_len) {
        req->cur_iov_idx++;
        req->cur_iov_oft = 0;
    } else { /* < */
        req->cur_iov_oft = bytes;
    }
}


static int client_submitter_send_cmd(struct nvme_qpair *vqp, nvme_req *req)
{
    void *saddr;
    int rem;
    int rc;

    assert(req->cmd_bytes < NVME_CMD_SZ);
    /* transfer cmd first */
    saddr = (void *)((uintptr_t)&req->cmd + req->cmd_bytes);
    rem = NVME_CMD_SZ - req->cmd_bytes;
    rc = leap_nonblock_write(vqp->cmd_sockfd, saddr, rem);
    if (rc <= 0) {
        return rc;
    }

    /* Coperd: at least >0 bytes are transfered */
    req->cmd_bytes += rc;
    //printf("Coperd,%s,req->cmd_bytes=%d\n", __func__, req->cmd_bytes);
    assert(req->cmd_bytes <= NVME_CMD_SZ);

    return rc;
}

/* TODO: copied from server_completer_send_data logic, need change? */
static int client_submitter_send_data(struct nvme_qpair *vqp, nvme_req *req)
{
    int rem_iovcnt;
    struct iovec *cur_iovec;
    int rc;

    rem_iovcnt = req->iovcnt - req->cur_iov_idx;
    cur_iovec = (struct iovec *)&req->iov[req->cur_iov_idx];
    cur_iovec[0].iov_base += req->cur_iov_oft;
    cur_iovec[0].iov_len -= req->cur_iov_oft;
    assert(cur_iovec[0].iov_len > 0);
    rc = leap_nonblock_writev(vqp->data_sockfd, cur_iovec, rem_iovcnt);
    if (rc < 0) {
        return rc;
    }

    /* restore the state if no successful byte transfer */
    cur_iovec[0].iov_base -= req->cur_iov_oft;
    cur_iovec[0].iov_len += req->cur_iov_oft;

    /* at least some bytes are successfully written */
    advance_req_iov_status(req, req->iov, rc);

    return rc;
}

static int client_submitter_rdma_process_write(struct nvme_qpair *vqp,
        nvme_req *req)
{
    struct rdma_context *rctx = vqp->rctx;

    leap_client_post_send(rctx, req);

    return 0;
}

static int client_submitter_tcp_process_write(struct nvme_qpair *vqp, nvme_req *req)
{
    int rc;

    /* transfer cmd first */
    if (req->cmd_bytes < NVME_CMD_SZ) {
        rc = client_submitter_send_cmd(vqp, req);
        if (rc < 0) {
            printf("Coperd,%s,%d,vqp[%d],socket failure,%d\n", __func__, __LINE__,
                    vqp->qid, rc);
            abort();
        } else if (rc == 0) {
            return 1;
        }

        //printf("Coperd,%s,req[%d],cmd_bytes=%d\n", __func__, req->id, req->cmd_bytes);
    }

    /* is cmd done? */
    if (req->cmd_bytes < NVME_CMD_SZ) {
        return 1;
    }

    /* cmd transfer is done */
#if 0
    printf("Coperd,%s,sendout write cmd,cid:%d\n", __func__, req->cmd.c.cid);
#endif
    assert(req->cmd_bytes == NVME_CMD_SZ);

    /* start data transfer */
    if (req->data_bytes < req->len) {
        rc = client_submitter_send_data(vqp, req);
        if (rc < 0) {
            printf("Coperd,%s,%d,vqp[%d],socket failure,%d\n", __func__, __LINE__,
                    vqp->qid, rc);
            abort();
        } else if (rc == 0) {
            return 1;
        }

        //printf("Coperd,%s,req[%d],data_bytes=%d\n", __func__, req->id, req->data_bytes);
    }

    if (req->data_bytes < req->len) {
        return 1;
    }

    assert(req->data_bytes == req->len);
    return 0;
}

static int client_submitter_rdma_process_read(struct nvme_qpair *vqp,
        nvme_req *req)
{
    struct rdma_context *rctx = vqp->rctx;

    leap_client_post_send(rctx, req);

    return 0;
}

static int client_submitter_tcp_process_read(struct nvme_qpair *vqp, nvme_req *req)
{
    int rc;

    /* transfer cmd first */
    if (req->cmd_bytes < NVME_CMD_SZ) {
        rc = client_submitter_send_cmd(vqp, req);
        if (rc < 0) {
            printf("Coperd,%s,%d,vqp[%d], socket failure,%d\n", __func__, __LINE__,
                    vqp->qid, rc);
            abort();
        } else if (rc == 0) {
            return 1;
        }
    }

    /* is cmd done? */
    if (req->cmd_bytes < NVME_CMD_SZ) {
        return 1;
    }

    /* cmd transfer is done, then read sending is done */
#if 0
    printf("Coperd,%s,sendout read cmd,cid:%d\n", __func__, req->cmd.c.cid);
#endif
    assert(req->cmd_bytes == NVME_CMD_SZ);
    return 0;
}

#define MAX_PCIE_BATCH_SZ       (32)

void client_completer_return_io(struct nvme_qpair *vqp, nvme_req *req);

static void client_submitter_pcie_process_pending_reqs(struct nvme_qpair *vqp)
{
    int nprocessed = 0;
    int nr_consumed = 0;
    nvme_req *req = NULL;
    struct leap *leap = vqp->leap;
    struct nvme_qpair *pqp;

    if ((vqp->leap->transport == LEAP_STRIPE) || (vqp->leap->transport == LEAP_RAID1))
	    pqp = &leap->pqps[vqp->qid + NR_DBVMS];
    else if (vqp->leap->transport == LEAP_PCIE && vqp->leap->use_rdma_for_vqp) {
        /* Coperd: for this case, vqp is already pqp, do nothing here */
        /* FIXME: UGLY UGLY */
        pqp = &leap->pqps[vqp->qid];
        assert(vqp == pqp);
    } else
	    pqp = &leap->pqps[vqp->qid];

    assert(pqp);
    /* process at most MAX submission to give others chances to run in time */
    while (nprocessed++ < MAX_PCIE_BATCH_SZ) {
        if (QTAILQ_EMPTY(&(vqp->submitter_pending_req_list))) {
            goto end;
        }
        req = QTAILQ_FIRST(&(vqp->submitter_pending_req_list));
        assert(req);

#ifdef DEBUG_VQP
        printf("Coperd,%s,vqp[%d],sending req[%d],len=%d,", __func__,
                vqp->qid, req->id, req->len);
        print_nvmecmd(&req->cmd);
#endif
        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            break;

        case NVME_CMD_WRITE:
            break;

        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,command not supported\n");
            abort();
        }

        /* write cmd to pSQ first */
#ifndef CORE_IOPS_TEST
        leap_write_cmd_to_psq(pqp, &req->cmd);
#endif

        nr_consumed++;

	assert(req->status == IN_SUBMITTER_P_LIST);
	QTAILQ_REMOVE(&vqp->submitter_pending_req_list, req, entry);

#if defined(__x86_64__)
        int rc;
        rc = femu_ring_enqueue(vqp->s2c_rq, (void **)&req, 1);
#ifndef CORE_IOPS_TEST
        if (rc != 1) {
            abort();
        }
#endif

#ifdef CORE_IOPS_TEST
	req->cpl.status = NVME_SUCCESS;
	req->cpl.cid = req->cmd.rw.cid;
	client_completer_return_io(vqp, req);

        //assert(req->status == IN_COMPLETER_P_LIST);
        //QTAILQ_REMOVE(&vqp->completer_pending_req_list, req, entry);
        rc = femu_ring_enqueue(vqp->c2s_rq, (void **)&req, 1);
        //assert(rc == 1);

	debug("core_iops_test: notified client\n");
#endif

#else
        /* Use a list */
        QTAILQ_INSERT_TAIL(&vqp->s2c_list, req, entry);
#endif

	if((vqp->leap->transport == LEAP_STRIPE) || (vqp->leap->transport == LEAP_RAID1))
		break;
    }

end:
    /* batch submissions if possible */
    if (nr_consumed > 0) {
        //printf("Coperd,ring pSQ[%d].DB=%d\n", pqp->qid, pqp->sq_tail);
#ifndef CORE_IOPS_TEST
        leap_ring_psq_doorbell(pqp, pqp->sq_tail);
#endif
    }
}

static void client_submitter_rdma_process_pending_reqs(struct nvme_qpair *vqp)
{
    int rc;
    int nprocessed = 0;
    nvme_req *req = NULL;

    /* process at most MAX submission to give others chances to run in time */
    while (nprocessed++ < MAX_RDMA_BATCH_SZ) {
        if (QTAILQ_EMPTY(&(vqp->submitter_pending_req_list))) {
            return;
        }
        req = QTAILQ_FIRST(&(vqp->submitter_pending_req_list));
        assert(req);

#ifdef DEBUG_VQP
            printf("Coperd,%s,vqp[%d],sending req[%d],len=%d,", __func__,
                    vqp->qid, req->id, req->len);
            print_nvmecmd(&req->cmd);
#endif
        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            rc = client_submitter_rdma_process_read(vqp, req);
            assert(rc == 0);
            break;

        case NVME_CMD_WRITE:
            rc = client_submitter_rdma_process_write(vqp, req);
            assert(rc == 0);
            break;

        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,command not supported,rc=%d\n", rc);
            abort();
        }

	// if raid1, don't remove the entry, save for local pcie req
	if(vqp->leap->transport != LEAP_RAID1) {
		assert(req->status == IN_SUBMITTER_P_LIST);
		QTAILQ_REMOVE(&vqp->submitter_pending_req_list, req, entry);
	}

#if defined(__x86_64__)
	// if raid1, no need to enqueue twice
	if(vqp->leap->transport != LEAP_RAID1) {
		rc = femu_ring_enqueue(vqp->s2c_rq, (void **)&req, 1);
		assert(rc == 1);
	}
#else
        QTAILQ_INSERT_TAIL(&vqp->s2c_list, req, entry);
#endif

	if((vqp->leap->transport == LEAP_STRIPE) || (vqp->leap->transport == LEAP_RAID1))
		break;
    }
}

/*
 * Coperd: we send all NVMe command through cmd_socket one by one
 * This makes sure that on the receving side, we can always identify new
 * requests by checking 64 bytes received
 * TODO: (1). OC command might contain extra data buffer beside prp list
 * (2). Batch optimizations ...
 */
static void client_submitter_tcp_process_pending_reqs(struct nvme_qpair *vqp)
{
    int rc;
    int nprocessed = 0;
    nvme_req *req = NULL;

    /* process at most MAX submission to give others chances to run in time */
    while (nprocessed++ < MAX_BATCH_SZ) {
        if (QTAILQ_EMPTY(&(vqp->submitter_pending_req_list))) {
            return;
        }
        req = QTAILQ_FIRST(&(vqp->submitter_pending_req_list));
        assert(req);

        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            rc = client_submitter_tcp_process_read(vqp, req);
            if (rc != 0) {
                /* not done, try next time */
                return;
            }
            break;

        case NVME_CMD_WRITE:
            rc = client_submitter_tcp_process_write(vqp, req);
            if (rc != 0) {
                return;
            }
#ifdef DEBUG_VQP
            printf("Coperd,%s,vqp[%d],sent-wr req[%d],len=%d,", __func__,
                    vqp->qid, req->id, req->len);
            print_nvmecmd(&req->cmd);
#endif
            break;

        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,command not supported\n");
            abort();
        }

        assert(req->status == IN_SUBMITTER_P_LIST);
        QTAILQ_REMOVE(&vqp->submitter_pending_req_list, req, entry);
#if defined(__x86_64__)
        rc = femu_ring_enqueue(vqp->s2c_rq, (void **)&req, 1);
        assert(rc == 1);
#else
        QTAILQ_INSERT_TAIL(&vqp->s2c_list, req, entry);
#endif
    }
}

static void client_submitter_stripe_process_pending_reqs(struct nvme_qpair *vqp)
{
	int nprocessed = 0;
	nvme_req *req = NULL;

	/* process at most MAX submission to give others chances to run in time */
	while (nprocessed++ < MAX_BATCH_SZ) {
		if (QTAILQ_EMPTY(&(vqp->submitter_pending_req_list))) {
			return;
		}
		req = QTAILQ_FIRST(&(vqp->submitter_pending_req_list));
		assert(req);

#ifdef DEBUG_PQP
		printf("this LBA: %lu\n", req->cmd.rw.slba);
#endif

		// striped at 16MB granularity
		if(((req->cmd.rw.slba / 4096) % 2) == 0) {
#ifdef DEBUG_PQP
			printf("issuing request to local SSD\n");
#endif
			client_submitter_pcie_process_pending_reqs(vqp);
		} else {
#ifdef DEBUG_PQP
			printf("issuing request to remote SSD\n");
#endif
			client_submitter_rdma_process_pending_reqs(vqp);
		}
	}
}


static void client_submitter_raid1_process_pending_reqs(struct nvme_qpair *vqp)
{
	int nprocessed = 0;
	nvme_req *req = NULL;

	/* process at most MAX submission to give others chances to run in time */
	while (nprocessed++ < MAX_BATCH_SZ) {
		if (QTAILQ_EMPTY(&(vqp->submitter_pending_req_list))) {
			return;
		}
		req = QTAILQ_FIRST(&(vqp->submitter_pending_req_list));
		assert(req);

#ifdef DEBUG_PQP
		printf("this LBA: %lu\n", req->cmd.rw.slba);
#endif

		// issue two requests, one to local SSD, one to remote
		client_submitter_rdma_process_pending_reqs(vqp);
		client_submitter_pcie_process_pending_reqs(vqp);
	}
}


/* translate NVMe commands to Azure blob requests */
static void client_submitter_azure_process_pending_reqs(struct nvme_qpair *vqp)
{
    int nprocessed = 0;
    nvme_req *req = NULL;

    while (nprocessed++ < MAX_BATCH_SZ) {
        if (QTAILQ_EMPTY(&(vqp->submitter_pending_req_list))) {
            return;
        }
        req = QTAILQ_FIRST(&(vqp->submitter_pending_req_list));
        assert(req);

#ifdef DEBUG_PQP
        printf("this LBA: %lu\n", req->cmd.rw.slba);
#endif

        req->cmd_bytes = NVME_CMD_SZ;

        debug("client_submitter_azure: op at %lu with count %lu\n",
                req->cmd.rw.slba * 4096, req->iovcnt);

        vqp->m_drive->enqueue_command(req->cmd.rw.opcode == NVME_CMD_READ?true:false,
                req->cmd.rw.slba * 4096,
                req->iov,
                req->iovcnt,
                req->cmd.rw.cid);
        debug("client_submitter_azure: enqueued new azure command, CID=%u\n",
                req->cmd.rw.cid);

        assert(req->status == IN_SUBMITTER_P_LIST);
        QTAILQ_REMOVE(&vqp->submitter_pending_req_list, req, entry);

#if defined(__x86_64__)
        int rc;
        rc = femu_ring_enqueue(vqp->s2c_rq, (void **)&req, 1);
        if (rc != 1) {
            abort();
        }
#else
        /* Use a list */
        QTAILQ_INSERT_TAIL(&vqp->s2c_list, req, entry);
#endif
    }

    debug("exiting client_submitter_azure");
}

/* Reset nvme_req except keeping ->id and ->iov fields */
static inline void client_reset_req(nvme_req *req)
{
#if 0
    int rid = req->id;

    if (req->iov) {
        free(req->iov);
    }
    memset(req, 0, sizeof(nvme_req));
    req->id = rid;
#endif

    memset(&req->cmd, 0, NVME_CMD_SZ);
    req->cid = -1;
    if (req->iov) {
        free(req->iov);
    }
    req->iovcnt = 0;
    req->cmd_bytes = 0;
    req->data_bytes = 0;
    memset(&req->cpl, 0, NVME_CPL_SZ);
    req->len = 0;
    req->is_write = false;
    req->cur_iov_idx = 0;
    req->cur_iov_oft = 0;

    /* need reset status field?? -> after drain_rq, it should be IN_REQ_LIST */
    if (req->status != IN_REQ_LIST) {
        printf("Coperd,WARNING,req initial status NOT IN_REQ_LIST\n");
        req->status = IN_REQ_LIST;
    }

    /* Don't touch riov, riovcnt, rbuf and rbuflen as they are pre-alloc'ed
     * and won't change across socp lifetime */
}

static void server_reset_req(nvme_req *req)
{
#if 0
    int rid = req->id;
    struct iovec *iov = req->iov;
    int iovcnt = req->iovcnt;

    memset(req, 0, sizeof(nvme_req));
    req->id = rid;
    /* for server, iov is pre-allocated, never free it */
    req->iov = iov;
    req->iovcnt = iovcnt;
    assert(req->iov);
#endif

    /* Reset fields except ->id, ->iov, ->iovcnt, ->entry */
    memset(&req->cmd, 0, sizeof(req->cmd));
    req->cid = -1;
    req->cmd_bytes = 0;
    req->data_bytes = 0;
    memset(&req->cpl, 0, sizeof(req->cpl));
    req->len = 0;
    req->is_write = false;
    req->cur_iov_idx = 0;
    req->cur_iov_oft = 0;
}

nvme_req *get_req_by_id(struct nvme_qpair *qp, int id)
{
    assert(id >= 0 && id < VQP_DEPTH);
    nvme_req *req = &qp->reqs[id];
    assert(req);

    return req;
}


#ifdef PSCHEDULE
/* check if we should exit QP entry forwarding */
int sched_sq_yield(struct leap *leap, int pr, int completed)
{
    leap->pr_cnt[pr].current += completed;

    if(leap->pr_cnt[pr].current >= leap->pr_cnt[pr].max) {
        debug("reached maximum, need to exit\n");
        return 1;
    }

    return 0;
}
#endif


#ifdef SNAPSHOTS
void convert_vcmd_to_pcmd_soc(nvme_req *req, nvme_req *rreq)
{
    /* Coperd: new req, cleanup the nvme_req structure first */
    //client_reset_req(req);
    server_reset_req(req);

    /* Coperd: copy 64B command to corresponding req */
    memcpy(&req->cmd, rreq->cmdbuf, NVME_CMD_SZ);
#ifdef DEBUG_VQP
    printf("Coperd,%s,%d: ", __func__, __LINE__);
    print_nvmecmd(&req->cmd);
#endif

}

void convert_vcmd_to_pcmd(nvme_req *req, struct nvme_command *vcmd)
{
	client_reset_req(req);
	struct nvme_command *pcmd = (struct nvme_command *)leap_vcmd_to_pcmd(vcmd);
	memcpy(&req->cmd, pcmd, NVME_CMD_SZ);
	/* fill iov and cid */
	client_parse_cmd(req);
}

void submit_to_pending_req_list(nvme_req *req, struct nvme_qpair *vqp)
{
    assert(req && req->status == IN_REQ_LIST);
    QTAILQ_REMOVE(&vqp->req_list, req, entry);
    QTAILQ_INSERT_TAIL(&vqp->submitter_pending_req_list, req, entry);
    req->status = IN_SUBMITTER_P_LIST;
}
#endif

/* TODO: maybe better do batching here too */
nvme_req *client_rdma_pcie_try_poll_cmd(struct leap *leap,
        struct nvme_qpair *vqp)
{
    struct rdma_context *rctx = vqp->rctx;
    nvme_req *rreq = NULL;
    struct ibv_wc wc;
    int rc;

    rc = ibv_poll_cq(rctx->cq, 1, &wc);
    if (rc < 0) {
        printf("Coperd,%s,ibv_poll_cq failed\n", __func__);
        abort();
    } else if (rc == 0) {
        /* Coperd: no cmd arrival, try next time */
        return NULL;
    }

    assert(rc == 1);

    if (wc.status != IBV_WC_SUCCESS) {
        printf("Coperd,%s,wc opcode: %d, RECV:%d,SEND:%d\n", __func__, wc.opcode,
                IBV_WC_RECV, IBV_WC_SEND);
        printf("Coperd,%s,Failed status %s (%d) for wr_id %d\n", __func__,
                ibv_wc_status_str(wc.status), wc.status, (int)wc.wr_id);
        abort();
    }

    switch (wc.opcode) {
    case IBV_WC_RECV:
        /* we only care about the cmd recv'ed */
        rreq = get_req_by_id(vqp, wc.wr_id);
        return rreq;

    case IBV_WC_SEND:
        return NULL;

    default:
        printf("Coperd,%s,Unknown WR type in CQ\n", __func__);
        abort();
    }

    return NULL;
}

#ifdef PSCHEDULE
int poll_vsq(struct leap *leap, struct nvme_qpair *vqp, int pr)
#else
int poll_vsq(struct leap *leap, struct nvme_qpair *vqp)
#endif
{
    nvme_req *req;
    struct nvme_command *vcmd, *pcmd;
    struct nvme_qpair *pqp;
    uint8_t spv;

#ifdef PSCHEDULE
    uint32_t ret = 0;
#endif

    /* Coperd: default path, using shared mem for vQP */
    if((leap->transport == LEAP_PCIE && leap->use_rdma_for_vqp == false) ||
       (leap->transport == LEAP_AZURE && leap->use_rdma_for_vqp == false) ||
       (leap->transport == LEAP_TCP && leap->use_rdma_for_vqp == false) ||
       (leap->transport == LEAP_RDMA && leap->use_rdma_for_vqp == false)) {

        //pthread_mutex_lock(&vqp->lock);
        spv = vqp_get_sp(vqp);
        if (spv == 0) {
            if (vqp_disabled(vqp, spv)) {
                printf("Coperd,%s,reset vqp[%d] ...\n", __func__, vqp->qid);
                leap_reinit_vqp(vqp);
                vqp->need_reset = false;
            }
            /* Coperd: vqp not ready, try luck next time */
            vqp->prev_spv = spv;
            //pthread_mutex_unlock(&vqp->lock);
            return -ENORDY;
        }

        //printf("Coperd,%s,sp_db=%d\n", __func__, sp);
        vsq_update_tail(vqp);
        while (vqp_get_sp(vqp) && !vsq_empty(vqp)) {
#ifdef DEBUG_VQP
            printf("Coperd,poll_vsq, draining rq\n");
#endif
            drain_rq(vqp, true);
            vcmd = (struct nvme_command *)&vqp->sq_cmds[vqp->sq_head];
            /* Coperd: we perform first round validaty check here, filter out
             * invalid commands instead of passing them through to OCSSD */
            if (!leap_vcmd_valid(vcmd)) {
                printf("ERROR,vqp[%d],sp:%d,t:%d,h:%d\n", vqp->qid, vqp_get_sp(vqp),
                        vqp->sq_tail, vqp->sq_head);
                if (!vqp_get_sp(vqp)) {
                    vqp->prev_spv = spv;
                    //pthread_mutex_unlock(&vqp->lock);
                    return -ERESET;
                    /* Coperd: we need to resyn vqp state */
                } else {
                    printf("ERROR,sp=1 but read invalid command from vSQ[%d]\n",
                            vqp->qid);
#ifdef DEBUG_VQP
                    printf("Coperd,%s,vSQ[%d],%d, ", __func__, vqp->qid, vqp->sq_head);
                    print_nvmecmd(vcmd);
#endif
                    vqp->prev_spv = spv;
                    //pthread_mutex_unlock(&vqp->lock);
                    abort();
                }

#ifdef LEAP_FAKE_VCQE_ON_INVAL_VSQE
                /* Coperd: fast fail, compose our own cqe, only for TESTING */
                leap_post_vcqe(vqp, status, vcmd->c.cid);
                vsq_inc_head(vqp);
                continue;
#endif
            }

#ifdef DEBUG_VQP
            printf("Coperd,%s,vSQ[%d],%d, ", __func__, vqp->qid, vqp->sq_head);
            print_nvmecmd(vcmd);
#endif

            /* Coperd: put new submissions to pending list first */
            assert(!QTAILQ_EMPTY(&vqp->req_list));

#ifdef USE_LEAP_CID
            req = QTAILQ_FIRST(&vqp->req_list);
#else
            req = get_req_by_id(vqp, vcmd->rw.cid);
#endif


#ifdef SNAPSHOTS
            if(req->cmd.rw.opcode == NVME_CMD_READ) {
                debug("snapshots: this is a read request\n");

                // read latest version from the log
                leap->log->read_latest_versions(req->iov, req->iovcnt, req->cmd.rw.slba * 4096);

            } else if(req->cmd.rw.opcode == NVME_CMD_WRITE) {
                debug("snapshots: this is a write request\n");

                // add new version to the log
                leap->log->add_version(req->iov, req->iovcnt, req->cmd.rw.slba * 4096,
                        vqp->qid, vcmd->rw.cid);

            } else { // flush operation (modprobe nvme)
                debug("snapshots: this is a flush operation\n");
            }

            if(req->cmd.rw.opcode == NVME_CMD_WRITE) {
                convert_vcmd_to_pcmd(req, vcmd);

                // Coperd: update vsq head
                vsq_inc_head(vqp);

                // same qid-cid pair shouldn't exist

                if(log_reqs.find(make_pair(vqp->qid, vcmd->rw.cid)) != log_reqs.end()) {
                    assert(0 && "snapshots: this entry exists in the log, aborting\n");
                } else {
                    debug("snapshots: adding new write entry to the log\n");
                    debug("snapshots: ID of this request %u\n", req->id);

                    // store req in htable for later processing
                    log_reqs.insert(make_pair(make_pair(vqp->qid, vcmd->rw.cid), req));
                    log_len += 1;
                }

                debug("snapshots: write is buffered in the log\n");

            } else {
                convert_vcmd_to_pcmd(req, vcmd);
                vsq_inc_head(vqp);
                submit_to_pending_req_list(req, vqp);
            }

#else

            client_reset_req(req);
            pcmd = (struct nvme_command *)leap_vcmd_to_pcmd(vcmd);
            memcpy(&req->cmd, pcmd, NVME_CMD_SZ);
            /* fill iov and cid */
            client_parse_cmd(req);
            /* Coperd: update vsq head */
            vsq_inc_head(vqp);

            assert(req && req->status == IN_REQ_LIST);
            QTAILQ_REMOVE(&vqp->req_list, req, entry);
            QTAILQ_INSERT_TAIL(&vqp->submitter_pending_req_list, req, entry);
            req->status = IN_SUBMITTER_P_LIST;
            //printf("Coperd,req[%d] inserted to submitter pending list\n", req->id);
#endif

#ifdef PSCHEDULE
            // stnovako: check if we should exit
            ret = ret + 1;

            if(sched_sq_yield(leap, pr, ret))
                break;
#endif
        }
        vqp->prev_spv = spv;
        //pthread_mutex_unlock(&vqp->lock);
    } else {
        /*
         ***********************************************************************
         **************** For routing vQP over RDMA ****************************
         ***********************************************************************
         */
        nvme_req *rreq;
        int cid;
        int reaped = 0;
        /* Coperd: we use the server logic to handle req to SSD directly */
        /* FIXME: hack hack hack */
        pqp = &leap->pqps[vqp->qid];
        vqp = pqp;

        while (reaped++ < 16) {
            drain_rq(vqp, true);
            rreq = client_rdma_pcie_try_poll_cmd(leap, vqp);
            if (!rreq) {
                continue;
            }

            cid = ((struct nvme_command *)rreq->cmdbuf)->rw.cid;
            req = get_req_by_id(vqp, cid);

            // SNAPSHOT code starts here	    
#ifdef SNAPSHOTS
            if(req->cmd.rw.opcode == NVME_CMD_READ) {
                debug("snapshots: this is a read request\n");

                // read latest version from the log
                leap->log->read_latest_versions(req->iov, req->iovcnt, req->cmd.rw.slba * 4096);

            } else if(req->cmd.rw.opcode == NVME_CMD_WRITE) {
                debug("snapshots: this is a write request\n");

                // add new version to the log
                leap->log->add_version(req->iov, req->iovcnt, req->cmd.rw.slba * 4096,
                        vqp->qid, cid); //vcmd->rw.cid);

            } else { // flush operation (modprobe nvme)
                debug("snapshots: this is a flush operation\n");
            }

            if(req->cmd.rw.opcode == NVME_CMD_WRITE) {
                convert_vcmd_to_pcmd_soc(req, rreq);

                // Coperd: update vsq head
                //vsq_inc_head(vqp);

                /* Need to post another RDMA recv req over rreq->cmdbuf */
                leap_client_post_recv2(vqp->rctx, rreq);

                /* fill iov and cid */
                //client_parse_cmd(req);
                server_prep_cmd(vqp, req);
                /* Coperd: update vsq head */
                //vsq_inc_head(vqp);

                // same qid-cid pair shouldn't exist

                if(log_reqs.find(make_pair(vqp->qid, cid)) != log_reqs.end()) {
                    assert(0 && "snapshots: this entry exists in the log, aborting\n");
                } else {
                    debug("snapshots: adding new write entry to the log\n");
                    debug("snapshots: ID of this request %u\n", req->id);

                    // store req in htable for later processing
                    log_reqs.insert(make_pair(make_pair(vqp->qid, cid), req));
                    log_len += 1;
                }

                debug("snapshots: write is buffered in the log\n");

            } else {
                convert_vcmd_to_pcmd_soc(req, rreq);
                //vsq_inc_head(vqp);
                /* Need to post another RDMA recv req over rreq->cmdbuf */
                leap_client_post_recv2(vqp->rctx, rreq);

                /* fill iov and cid */
                //client_parse_cmd(req);
                server_prep_cmd(vqp, req);
                /* Coperd: update vsq head */
                //vsq_inc_head(vqp);

                submit_to_pending_req_list(req, vqp);
            }

#else

            /* Coperd: new req, cleanup the nvme_req structure first */
            //client_reset_req(req);
            server_reset_req(req);

            /* Coperd: copy 64B command to corresponding req */
            memcpy(&req->cmd, rreq->cmdbuf, NVME_CMD_SZ);
#ifdef DEBUG_VQP
            printf("Coperd,%s,%d: ", __func__, __LINE__);
            print_nvmecmd(&req->cmd);
#endif
            /* Need to post another RDMA recv req over rreq->cmdbuf */
            leap_client_post_recv2(vqp->rctx, rreq);

            /* fill iov and cid */
            //client_parse_cmd(req);
            server_prep_cmd(vqp, req);
            /* Coperd: update vsq head */

#ifdef CORE_IOPS_TEST // LATEST
            vsq_inc_head(vqp);
#else
            if((vqp->leap->transport == LEAP_AZURE) || (vqp->leap->transport == LEAP_TCP))
                vsq_inc_head(vqp);
#endif


#ifndef ABC
            assert(req && req->status == IN_REQ_LIST);
            QTAILQ_REMOVE(&vqp->req_list, req, entry);
            QTAILQ_INSERT_TAIL(&vqp->submitter_pending_req_list, req, entry);
            req->status = IN_SUBMITTER_P_LIST;
#endif

#endif

#ifdef PSCHEDULE
            ret = ret + 1;

            if(sched_sq_yield(leap, pr, ret))
                break;
#endif


#ifdef ABC
            //if(hash_cache.find(req->cmd.rw.slba) == hash_cache.end()) {
            uint8_t *addr;
            if (!abc_is_block_cached(req->cmd.rw.slba, &addr)) {
                printf("[ABC] adding LBA %lu to the cache\n", req->cmd.rw.slba);
                //printf("hash cache: ID of this request %u\n", req->id);

                // store req in htable for later processing
                //hash_cache.insert(make_pair(req->cmd.rw.slba, 1));
                abc_get_block_entry(req->cmd.rw.slba, &addr);

                assert(req && req->status == IN_REQ_LIST);
                QTAILQ_REMOVE(&vqp->req_list, req, entry);
                QTAILQ_INSERT_TAIL(&vqp->submitter_pending_req_list, req, entry);
                req->status = IN_SUBMITTER_P_LIST;

            } else {
                assert(req && req->status == IN_REQ_LIST);
                QTAILQ_REMOVE(&vqp->req_list, req, entry);

                debug("hash cache: CACHE HIT.. Azure lookup not required\n");

                /* For vQP routing via RDMA */
                /* We need to send CPL back to WPT and it post completions for us */
                struct nvme_completion *cqe = &req->cpl;

                /* Fake completion here */
                cqe->status = NVME_SUCCESS;
                cqe->cid = req->cmd.rw.cid;
                leap_pcqe_to_vcqe(vqp, cqe);

#ifdef DEBUG_VQP
                printf("Coperd,%s,%d,vCQ[%d],%d, ", __func__, __LINE__, vqp->qid,
                        vqp->cq_tail);
                print_nvmecqe(cqe);
#endif

                /* Coperd: TODO: how do we know if the vQP has been reset? */
                vcq_inc_tail(vqp);

                memcpy(req->cplbuf, cqe, NVME_CPL_SZ);
                // copy data. right now only able to ship 4K of data
                //memcpy(req->cplbuf + NVME_CPL_SZ, addr, RBUF_SIZE - NVME_CPL_SZ - NVME_CMD_SZ);

                /* Coperd: send CPL in req->cplbuf back to WPT for cpl handling */
                leap_client_post_send2(vqp->rctx, req);
                /* For SVK */
                QTAILQ_INSERT_TAIL(&vqp->c2s_list, req, entry);
            }
#endif

#ifdef CORE_IOPS_TEST

            /* For vQP routing via RDMA */
            /* We need to send CPL back to WPT and it post completions for us */
            struct nvme_completion *cqe = &req->cpl;

            /* Fake completion here */
            cqe->status = NVME_SUCCESS;
            cqe->cid = req->cmd.rw.cid;
            leap_pcqe_to_vcqe(vqp, cqe);

#ifdef DEBUG_VQP
            printf("Coperd,%s,%d,vCQ[%d],%d, ", __func__, __LINE__, vqp->qid,
                    vqp->cq_tail);
            print_nvmecqe(cqe);
#endif

            /* Coperd: TODO: how do we know if the vQP has been reset? */
            vcq_inc_tail(vqp);
            /* Coperd: ok, send virtual interrupt */
            //vqp_inc_si(vqp);

            memcpy(req->cplbuf, cqe, NVME_CPL_SZ);
            /* Coperd: send CPL in req->cplbuf back to WPT for cpl handling */
            leap_client_post_send2(vqp->rctx, req);
            /* For SVK */
            //femu_ring_enqueue(vqp->c2s_rq, (void **)&req, 1);
            QTAILQ_INSERT_TAIL(&vqp->c2s_list, req, entry);
#endif

        }
        }

        // IMPORTANT: need to remove when running QL-VM IOPS_TEST
#ifdef CORE_IOPS_TEST
        return 0;
#endif

        /* Coperd: do cmd & data transfer for reqs in pending list */
        if (leap->transport == LEAP_PCIE) {
            client_submitter_pcie_process_pending_reqs(vqp);
        } else if (leap->transport == LEAP_TCP) {
            client_submitter_tcp_process_pending_reqs(vqp);
        } else if (leap->transport == LEAP_RDMA) {
            client_submitter_rdma_process_pending_reqs(vqp);
        } else if(leap->transport == LEAP_STRIPE) {
            client_submitter_stripe_process_pending_reqs(vqp);
        } else if(leap->transport == LEAP_RAID1) {
            client_submitter_raid1_process_pending_reqs(vqp);
        } else if(leap->transport == LEAP_AZURE) {
            client_submitter_azure_process_pending_reqs(vqp);
        }

#ifdef PSCHEDULE
        return ret;
#else
        return 0;
#endif
    }

#ifdef SNAPSHOTS
void flush_log(struct leap *leap)
{
    /* go through all pending log entries and flush them */
    for (unsigned int i = 0; i < log_len; i++) {
        struct iovec* iov = NULL;
        int count = 0;
        off_t offset;
        uint16_t vqp_id;
        uint16_t cid;

        nvme_req *req;

        for (;;) {
            bool found = false;
            count = 0;
            iov = NULL;

            leap->log->peek_oldest_version(found, iov, count, offset, vqp_id, cid);

            if (found) {
                iov = new struct iovec[count];
                found = false;
                leap->log->peek_oldest_version(found, iov, count, offset, vqp_id, cid);

                if (found) {
                    debug("snapshots: found this vqp and cid: %u %u\n", vqp_id, cid);

                    // check if log entry exists in htable (req)
                    if (log_reqs.find(make_pair(vqp_id, cid)) == log_reqs.end())
                        assert(0 && "snapshots: nvme_req not found in the htable\n");
                    else
                        debug("snapshots: found pending request in the log\n");

                    req = log_reqs[make_pair(vqp_id, cid)];

                    // enqueue req for further processing
                    assert(req && req->status == IN_REQ_LIST);
                    QTAILQ_REMOVE(&leap->vqps[vqp_id].req_list, req, entry);
                    QTAILQ_INSERT_TAIL(&leap->vqps[vqp_id].submitter_pending_req_list, req, entry);
                    req->status = IN_SUBMITTER_P_LIST;

                    // remove oldest version (log and htable)
                    leap->log->pop_oldest_version();
                    log_reqs.erase(make_pair(vqp_id, cid));

                    debug("snapshots: removed oldest version from the log\n");                                     \


                } else {
                    assert(0 && "snapshots: log entry missing, aborting\n");
                }

                delete[] iov;
                break;
            }
        }
    }

    // reset log counter
    log_len = 0;

    // process enqueued requests vQP->pQP
    if (leap->transport == LEAP_PCIE) {
        client_submitter_pcie_process_pending_reqs(&leap->vqps[1]);
        client_submitter_pcie_process_pending_reqs(&leap->vqps[2]);
    } else {
        assert(0 && "snapshots only work with PCIe");
    }
}
#endif

#ifdef PSCHEDULE
// pick next QP using work-conserving-strict scheduling
int sched_get_next_sq(struct leap *leap, int pr, int completed)
{
	static unsigned long poll_cnt = 0;

	assert(leap->pr_cnt[0].max >= PR1);
	assert(leap->pr_cnt[1].max >= PR1);

	assert(leap->pr_cnt[0].max <= PR0);
	assert(leap->pr_cnt[1].max <= PR0);

	/* processed new vQP entries in the previous iter? */
	if (completed > 0) {
		// if PR0 active, reset weights and counters
		if (pr == 0) {
			poll_cnt = 0;

			leap->pr_cnt[0].max = PR0;
			leap->pr_cnt[1].max = PR1;

			if (leap->pr_cnt[0].current < leap->pr_cnt[0].max) {
				return 1;
			}
		}

		// PR0 consumed credit, on to PR1
		if (leap->pr_cnt[1].current < leap->pr_cnt[1].max) {
			leap->pr_cnt[0].current = 0;
			return 2;
		} else {
			// both classes consumed, wrap around
			leap->pr_cnt[0].current = 0;
			leap->pr_cnt[1].current = 0;

			return 1;
		}
    } else {
        if (pr == 0) {
            if (poll_cnt > RETRY) {
                // if PR0 idle, increase PR1 weight - decrease PR0
                leap->pr_cnt[0].max = get_max(leap->pr_cnt[0].max - 1, (unsigned)PR1);
                leap->pr_cnt[1].max = get_min(leap->pr_cnt[1].max + 1, (unsigned)PR0);

                return 2;
            } else {
                // else count one empty poll
                poll_cnt += 1;

                return 1;
            }
        }
    }

	return 1;
}


int poll_vsqs(struct leap *leap)
{
    struct nvme_qpair *vqps = leap->vqps;
    struct nvme_qpair *vqp;
    int ret;

    // first check PR0
    static int i = 1;

    vqp = &vqps[i];

    ret = poll_vsq(leap, vqp, i-1);
    if (ret == -ERESET) {
    } else if (ret == -ESQMAP) {
        /* Coperd: vqp is not mapped correctly */
        printf("\n\n\nvqp[%d],spdb:%d,sqdb:%d,cqdb:%d,t:%d,h:%d\n\n\n",
                vqp->qid, *(vqp->sp_db), *(vqp->sq_db), *(vqp->cq_db),
                vqp->sq_tail, vqp->sq_head);
        sleep(1);
    }

    // pick the next queue
    i = sched_get_next_sq(leap, i-1, ret);

#ifdef SNAPSHOTS
    // TODO: do we want to flush only when writer selected?
    // and/or do we want to flush every Nth iteration?
    flush_log(leap);
#endif

    return 0;
}

#else

int poll_vsqs(struct leap *leap)
{
    int i;
    struct nvme_qpair *vqps = leap->vqps;
    struct nvme_qpair *vqp;
    int ret;

    for (i = 1; i <= NR_DBVMS/*leap->nr_vqps*/; i++) {
        vqp = &vqps[i];

        ret = poll_vsq(leap, vqp);
        if (ret == -ERESET) {
        } else if (ret == -ESQMAP) {
            /* Coperd: vqp is not mapped correctly */
            printf("\n\n\nvqp[%d],spdb:%d,sqdb:%d,cqdb:%d,t:%d,h:%d\n\n\n",
                    vqp->qid, *(vqp->sp_db), *(vqp->sq_db), *(vqp->cq_db),
                    vqp->sq_tail, vqp->sq_head);
            sleep(1);
        }

#ifdef SNAPSHOTS
	// TODO: do we want to flush only when writer selected?
	// and/or do we want to flush every Nth iteration?
	flush_log(leap);
#endif

    }

    return 0;
}
#endif


static int server_submitter_recv_cmd(struct nvme_qpair *pqp)
{
    int rem;
    void *cmdbuf;
    int rc;

    cmdbuf = (void *)((uintptr_t)&pqp->cmd + pqp->cmd_bytes);
    rem = NVME_CMD_SZ - pqp->cmd_bytes;
    /* try to some something from the sock */
    rc = leap_nonblock_read(pqp->cmd_sockfd, cmdbuf, rem);
    if (rc <= 0) {
        return rc;
    }

    pqp->cmd_bytes += rc;
#ifdef DEBUG_PQP
    printf("Coperd,%s,pqp[%d],cmd_bytes=%d\n", __func__, pqp->qid, pqp->cmd_bytes);
#endif
    assert(pqp->cmd_bytes <= NVME_CMD_SZ);
    return rc;
}

static int server_submitter_recv_data(struct nvme_qpair *pqp, nvme_req *req)
{
    int rem_iovcnt;
    struct iovec *cur_iovec;
    int rc;

    rem_iovcnt = req->iovcnt - req->cur_iov_idx;
    cur_iovec = (struct iovec *)&req->iov[req->cur_iov_idx];
    cur_iovec[0].iov_base += req->cur_iov_oft;
    cur_iovec[0].iov_len -= req->cur_iov_oft;
    assert(cur_iovec[0].iov_len > 0);
    rc = leap_nonblock_readv(pqp->data_sockfd, cur_iovec, rem_iovcnt);
    if (rc < 0) {
        return rc;
    }

    /* restore the state if no successful byte transfer */
    cur_iovec[0].iov_base -= req->cur_iov_oft;
    cur_iovec[0].iov_len += req->cur_iov_oft;

    /* at least some bytes are successfully written */
    advance_req_iov_status(req, req->iov, rc);

    return rc;
}

/* TODO: maybe better do batching here too */
nvme_req *server_submitter_rdma_try_poll_cmd(struct leap *leap,
        struct nvme_qpair *pqp)
{
    struct rdma_context *rctx = pqp->rctx;
    nvme_req *rreq = NULL;
    struct ibv_wc wc;
    int rc;

    rc = ibv_poll_cq(rctx->cq, 1, &wc);
    if (rc < 0) {
        printf("Coperd,%s,ibv_poll_cq failed\n", __func__);
        abort();
    } else if (rc == 0) {
        /* Coperd: no cmd arrival, try next time */
        return NULL;
    }

    assert(rc == 1);

    if (wc.status != IBV_WC_SUCCESS) {
        printf("Coperd,%s,wc opcode: %d, RECV:%d,SEND:%d\n", __func__, wc.opcode,
                IBV_WC_RECV, IBV_WC_SEND);
        printf("Coperd,%s,Failed status %s (%d) for wr_id %d\n", __func__,
                ibv_wc_status_str(wc.status), wc.status, (int)wc.wr_id);
        abort();
    }

    /* find corresponding req associated with this cpl */

    switch (wc.opcode) {
    case IBV_WC_RECV:
        /* RDMA server only care about the cmd recv'ed */
        rreq = get_req_by_id(pqp, wc.wr_id);
        return rreq;

    case IBV_WC_SEND:
        return NULL;

    default:
        printf("Coperd,%s,Unknown WR type in CQ\n", __func__);
        abort();
    }

    return NULL;
}

static void server_submitter_rdma_waitfor_reqs(struct nvme_qpair *pqp)
{
    struct leap *leap = pqp->leap;
    nvme_req *req = NULL, *rreq = NULL;
    int cid;
    int n = 0;

    while (n++ < MAX_BATCH_SZ) {
        drain_rq(pqp, true);

        /* rreq: we only care about rreq->rbuf which contains cmd */
        rreq = server_submitter_rdma_try_poll_cmd(leap, pqp);
        if (!rreq) {
            return;
        }

        cid = ((struct nvme_command *)rreq->rbuf)->rw.cid;
        req = get_req_by_id(pqp, cid);

        server_reset_req(req);
        memcpy(&req->cmd, rreq->rbuf, NVME_CMD_SZ);
#ifdef DEBUG_PQP
        printf("Coperd,%s,req->id=%d,", __func__, req->id);
        print_nvmecmd(&req->cmd);
#endif

        /* it's safe to caLL it here as it only depends on req->cmd */
        server_prep_cmd(pqp, req);

        leap_server_copy_data_from_rbuf(req, rreq->rbuf);


        /* USE THE SAME CID AS CLIENT */
#if 0
        /*
         * UGLY: for RDMA, we have to save cid from cmd to find corresponding
         * req from cpl, TODO TODO TODO
         */
        req->cid = req->cmd.rw.cid;
        req->cmd.c.cid = req->id;
#endif

        /* rbuf is no longer being used, post it as recv again */
        leap_server_post_recv(pqp->rctx, rreq);

        /* Coperd: send to submitter list for further processing */
        assert(req);
        assert(req->status == IN_REQ_LIST);
        QTAILQ_REMOVE(&pqp->req_list, req, entry);
        QTAILQ_INSERT_TAIL(&pqp->submitter_pending_req_list, req, entry);
        req->status = IN_SUBMITTER_P_LIST;
    }
}

static void server_submitter_waitfor_reqs(struct nvme_qpair *pqp)
{
    nvme_req *req;
    int n = 0;
    int rc;

    while (n++ < MAX_BATCH_SZ) {
        drain_rq(pqp, true);
        if (pqp->cmd_bytes < NVME_CMD_SZ) {
            rc = server_submitter_recv_cmd(pqp);
            if (rc < 0) {
                printf("Coperd,%s,%d,pqp[%d],cmd socket failure,%d\n", __func__,
                        __LINE__, pqp->qid, rc);
                abort();
            } else if (rc == 0) {
                /* can go to process reqs in submitter_pending_list */
                return;
            }
        }

        if (pqp->cmd_bytes < NVME_CMD_SZ) {
            return;
        }

        /* we do have recv a cmd */
        assert(pqp->cmd_bytes == NVME_CMD_SZ);
        assert(!QTAILQ_EMPTY(&pqp->req_list));
#ifdef USE_LEAP_CID
        req = QTAILQ_FIRST(&pqp->req_list);
#else
        req = get_req_by_id(pqp, pqp->cmd.rw.cid);
#endif
        assert(req && req->status == IN_REQ_LIST);
        QTAILQ_REMOVE(&pqp->req_list, req, entry);
        server_reset_req(req);
        req->cmd = pqp->cmd;
        server_prep_cmd(pqp, req);
        /* Coperd: send to submitter list for further processing */
        QTAILQ_INSERT_TAIL(&pqp->submitter_pending_req_list, req, entry);
        req->status = IN_SUBMITTER_P_LIST;

        memset(&pqp->cmd, 0, sizeof(pqp->cmd));
        pqp->cmd_bytes = 0;
    }
}

static void server_submitter_rdma_process_incoming_reqs(struct nvme_qpair *pqp)
{
    nvme_req *req = NULL;
    int nprocessed = 0;

    /* req_list -> submitter_pending_req_list */
    server_submitter_rdma_waitfor_reqs(pqp);

    /* submitter_pending_req_list -> s2c_rq */
    while (nprocessed++ < MAX_BATCH_SZ) {
        if (QTAILQ_EMPTY(&pqp->submitter_pending_req_list)) {
            return;
        }
        req = QTAILQ_FIRST(&pqp->submitter_pending_req_list);
        assert(req);

        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            /* for read, no data needs to transfer, so we submit it to pQP */
            break;
        case NVME_CMD_WRITE:
            /* for write, with RDMA, we recv cmd and data at the same time */
            break;
        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,%s,not supported command type\n", __func__);
            abort();
        }

        assert(req->status == IN_SUBMITTER_P_LIST);
        QTAILQ_REMOVE(&pqp->submitter_pending_req_list, req, entry);
#if defined(__x86_64__)
        int rc;
        rc = femu_ring_enqueue(pqp->s2c_rq, (void **)&req, 1);
#ifdef DEBUG_RTE_RING
        printf("Coperd,%s,pqp[%d],enqueue req[%d] to s2c_rq\n", __func__,
                pqp->qid, req->id);
#endif
        if (rc != 1) {
            abort();
        }
#else
        QTAILQ_INSERT_TAIL(&pqp->s2c_list, req, entry);
#endif
        /* submit the command to pSQ */
        leap_submit_pcmd(pqp, &req->cmd);
    }
}

static void server_submitter_process_incoming_reqs(struct nvme_qpair *pqp)
{
    nvme_req *req = NULL;
    int nprocessed = 0;
    int rc;

    /* req_list -> submitter_pending_req_list */
    server_submitter_waitfor_reqs(pqp);

    /* submitter_pending_req_list -> s2c_rq */
    while (nprocessed++ < MAX_BATCH_SZ) {
        if (QTAILQ_EMPTY(&pqp->submitter_pending_req_list)) {
            return;
        }
        req = QTAILQ_FIRST(&pqp->submitter_pending_req_list);
        assert(req);

        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            /* for read, no data needs to transfer, so we submit it to pQP */
            /* TODO: we need allocate a new buffer for this command! */
            break;
        case NVME_CMD_WRITE:
            /* recv the data, then submit this cmd to pSQ */
            if (req->data_bytes < req->len) {
                rc = server_submitter_recv_data(pqp, req);
                if (rc < 0) {
                    printf("Coperd,%s,%d,pqp[%d],socket failure,%d\n", __func__,
                            __LINE__, pqp->qid, rc);
                    abort();
                } else if (rc == 0) {
                    return;
                }
            }
            /* data transfer done? */
            if (req->data_bytes < req->len) {
                return;
            }
            assert(req->data_bytes == req->len);
#ifdef DEBUG_PQP
            printf("Coperd,%s,pqp[%d],req[%d],recv-wr-cmd-data,len=%d\n",
                    __func__, pqp->qid, req->id, req->len);
#endif
            break;
        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,%s,not supported command type\n", __func__);
            abort();
        }

        assert(req->status == IN_SUBMITTER_P_LIST);
        QTAILQ_REMOVE(&pqp->submitter_pending_req_list, req, entry);
#if defined(__x86_64__)
        rc = femu_ring_enqueue(pqp->s2c_rq, (void **)&req, 1);
#ifdef DEBUG_RTE_RING
        printf("Coperd,%s,pqp[%d],enqueue req[%d] to s2c_rq\n", __func__,
                pqp->qid, req->id);
#endif
        assert(rc == 1);
#else
        QTAILQ_INSERT_TAIL(&pqp->s2c_list, req, entry);
#endif

	debug("[TCP] Received new command, now submitting to pSQ\n");
	
        /* submit the command to pSQ */
        leap_submit_pcmd(pqp, &req->cmd);
    }
}

bool leap_pcqe_valid(struct nvme_qpair *pqp, uint16_t head, uint16_t phase)
{
    return ((le16_to_cpu(pqp->cqes[head].status) & 1) == phase);
}

bool leap_read_pcqe(struct nvme_qpair *pqp, struct nvme_completion *pcqe)
{
    if (leap_pcqe_valid(pqp, pqp->cq_head, pqp->cq_phase)) {
        memcpy((void *)pcqe, (void *)&pqp->cqes[pqp->cq_head], sizeof(*pcqe));

        if (++pqp->cq_head == pqp->q_depth) {
            pqp->cq_head = 0;
            pqp->cq_phase = !pqp->cq_phase;
        }

        return true;
    }

    return false;
}

struct nvme_qpair *pqp_get_mapping_vqp(struct leap *leap, struct nvme_qpair *pq)
{
    struct nvme_qpair *vqps = leap->vqps;

    /* Coperd: only safe for 1:1 vQP to pQP mapping; TODO TODO */
    struct nvme_qpair *vqp = &vqps[pq->qid];

    return vqp;
}

/* Coperd: cqe is a copy of the corresponding physical entry */
void leap_pcqe_to_vcqe(struct nvme_qpair *vqp, struct nvme_completion *cqe)
{
	uint16_t status;

#ifdef FAKE_SUCCESS_CPL
	/* For Debugging: always fake success */
	status = le16_to_cpu(0) >> 1;
#else
	status = le16_to_cpu(cqe->status) >> 1;
#endif
	cqe->sq_id = cpu_to_le16(vqp->qid);
	/* Coperd: for vQP over RDMA, we only need to route original CQE back */
	//if (!vqp->leap->use_rdma_for_vqp) { // LATEST: comment
#ifdef CORE_IOPS_TEST
	cqe->status = cpu_to_le16(status << 1 | vqp->cq_phase);
	cqe->sq_head = cpu_to_le16(vqp->sq_head);
#else
	if (!vqp->leap->use_rdma_for_vqp) {
		cqe->status = cpu_to_le16(status << 1 | vqp->cq_phase);
		cqe->sq_head = cpu_to_le16(vqp->sq_head);
	} else {
		if((vqp->leap->transport == LEAP_AZURE) || (vqp->leap->transport == LEAP_TCP)) {
			cqe->status = cpu_to_le16(status << 1 | vqp->cq_phase);
			cqe->sq_head = cpu_to_le16(vqp->sq_head);
		}
	}
#endif
}

int leap_handle_pcqe(struct leap *leap, struct nvme_qpair *pqp,
        struct nvme_completion *cqe)
{
    if (cqe->cid >= pqp->q_depth) {
        printf("Coperd,pqp[%d],invalid id %d completed on queue %d\n", pqp->qid,
                cqe->cid, cqe->sq_id);
        abort();
    }

#ifdef DEBUG_PQP
    printf("Coperd,%s,pCQ[%d],%d, ", __func__, pqp->qid, pqp->cq_head);
    print_nvmecqe(cqe);
#endif

    //pthread_mutex_lock(&vqp->lock);
    //pthread_mutex_unlock(&vqp->lock);

    return 0;
}

static inline void leap_ring_pcq_doorbell(struct nvme_qpair *pqp)
{
    uint16_t head = pqp->cq_head;

    leap_mmio_write_4(pqp->cq_db, head);
}

static int64_t nr_processed = 0;

/*
 * @ret same as leap_nonblock_write(), but with transfer state updated
 */
static int server_completer_send_cpl(struct nvme_qpair *pqp, nvme_req *req)
{
    int rem;
    void *cplbuf;
    int rc;

    rem = NVME_CPL_SZ - req->cmd_bytes;
    cplbuf = (void *)((uintptr_t)&req->cpl + req->cmd_bytes);
    rc = leap_nonblock_write(pqp->cmd_sockfd, cplbuf, rem);
    if (rc <= 0) {
        return rc;
    }

    req->cmd_bytes += rc;
    assert(req->cmd_bytes <= NVME_CPL_SZ);
    return rc;
}

static int server_completer_send_data(struct nvme_qpair *pqp, nvme_req *req)
{
    int rem_iovcnt;
    struct iovec *cur_iovec;
    int rc;

    rem_iovcnt = req->iovcnt - req->cur_iov_idx;
    cur_iovec = (struct iovec *)&req->iov[req->cur_iov_idx];
    cur_iovec[0].iov_base += req->cur_iov_oft;
    cur_iovec[0].iov_len -= req->cur_iov_oft;
    assert(cur_iovec[0].iov_len > 0);
    rc = leap_nonblock_writev(pqp->data_sockfd, cur_iovec, rem_iovcnt);
    if (rc < 0) {
        return rc;
    }

    /* restore the state if no successful byte transfer */
    cur_iovec[0].iov_base -= req->cur_iov_oft;
    cur_iovec[0].iov_len += req->cur_iov_oft;

    /* at least some bytes are successfully written */
    advance_req_iov_status(req, req->iov, rc);

    return rc;
}

static int server_completer_rdma_process_read(struct nvme_qpair *pqp,
        nvme_req *req)
{
    struct rdma_context *rctx = pqp->rctx;

    // copy data to rbuf first
    // TODO: do it here or inside post_send?
    leap_server_copy_data_to_sbuf(req);

    // post send
    leap_server_post_send(rctx, req);

    return 0;
}

static int server_completer_process_read(struct nvme_qpair *pqp, nvme_req *req)
{
    int rc;
    /* send data first */
    if (req->data_bytes < req->len) {
	    debug("[TCP] Sending back the data\n");
        rc = server_completer_send_data(pqp, req);
        if (rc < 0) {
            printf("Coperd,%s,%d,pqp[%d],socket failure,%d\n", __func__,
                    __LINE__, pqp->qid, rc);
            abort();
        } else if (rc == 0) {
            return 1;
        }
    }

    /* data transfer done? */
    if (req->data_bytes < req->len) {
        return 1;
    }

    /* ok, data done, send cpl now */
    assert(req->data_bytes == req->len);
    if (req->cmd_bytes < NVME_CPL_SZ) {
	    debug("[TCP] Sending back the CPL\n");
        rc = server_completer_send_cpl(pqp, req);
        if (rc < 0) {
            printf("Coperd,%s,%d,pqp[%d],socket failure,%d\n", __func__,
                    __LINE__, pqp->qid, rc);
            abort();
        } else if (rc == 0) {
            return 1;
        }
    }

    if (req->cmd_bytes < NVME_CPL_SZ) {
        return 1;
    }

    assert(req->cmd_bytes == NVME_CPL_SZ);
    return 0;
}

static int server_completer_rdma_process_write(struct nvme_qpair *pqp,
        nvme_req *req)
{
    struct rdma_context *rctx = pqp->rctx;

    leap_server_post_send(rctx, req);

    return 0;
}

static int server_completer_process_write(struct nvme_qpair *pqp, nvme_req *req)
{
    int rc;

    if (req->cmd_bytes < NVME_CPL_SZ) {
        rc = server_completer_send_cpl(pqp, req);
        if (rc < 0) {
            printf("Coperd,%s,%d,pqp[%d],socket failure,%d\n", __func__,
                    __LINE__, pqp->qid, rc);
            abort();
        } else if (rc == 0) {
            return 1;
        }
    }

    if (req->cmd_bytes < NVME_CPL_SZ) {
        return 1;
    }

    assert(req->cmd_bytes == NVME_CPL_SZ);
    return 0;
}

void server_completer_rdma_process_cpls(struct leap *leap, struct nvme_qpair *pqp)
{
    int reaped = 0;
    nvme_req *req;
    int rc;

    /* Now, let's process cpl and send it back to client */
    while (reaped++ <= MAX_BATCH_SZ) {
        if (QTAILQ_EMPTY(&pqp->cpl_pending_req_list)) {
            return;
        }
        req = QTAILQ_FIRST(&pqp->cpl_pending_req_list);
        assert(req);

        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            rc = server_completer_rdma_process_read(pqp, req);
            assert(rc == 0);
            break;

        case NVME_CMD_WRITE:
            rc = server_completer_rdma_process_write(pqp, req);
            if (rc != 0) {
                return;
            }
#ifdef DEBUG_PQP
            printf("Coperd,pqp[%d],sent-wr-cpl req[%d],len=%d,", pqp->qid,
                    req->id, req->len);
            print_nvmecmd(&req->cmd);
#endif
            break;

        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,%s,cmd type not supported yet\n", __func__);
            abort();
        }

        /* complete one */
        assert(!QTAILQ_EMPTY(&pqp->cpl_pending_req_list));
        assert(req->status == IN_CPL_P_LIST);
        QTAILQ_REMOVE(&pqp->cpl_pending_req_list, req, entry);
#if defined(__x86_64__)
        rc = femu_ring_enqueue(pqp->c2s_rq, (void **)&req, 1);
        assert(rc == 1);
#else
        QTAILQ_INSERT_TAIL(&pqp->c2s_list, req, entry);
#endif
        /* next time, we can continue handle next avail completion */
    }
}

void server_completer_process_cpls(struct leap *leap, struct nvme_qpair *pqp)
{
    int reaped = 0;
    nvme_req *req;
    int rc;

    /* Now, let's process cpl and send it back to client */
    while (reaped++ <= MAX_BATCH_SZ) {
        if (QTAILQ_EMPTY(&pqp->cpl_pending_req_list)) {
            return;
        }
        req = QTAILQ_FIRST(&pqp->cpl_pending_req_list);
        assert(req);
        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            rc = server_completer_process_read(pqp, req);
            if (rc != 0) {
                return;
            }
            break;
        case NVME_CMD_WRITE:
            rc = server_completer_process_write(pqp, req);
            if (rc != 0) {
                return;
            }
#ifdef DEBUG_PQP
            printf("Coperd,pqp[%d],sent-wr-cpl req[%d],len=%d,", pqp->qid,
                    req->id, req->len);
            print_nvmecmd(&req->cmd);
#endif
            break;
        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,%s,cmd type not supported yet\n", __func__);
            abort();
        }

        /* complete one */
        assert(!QTAILQ_EMPTY(&pqp->cpl_pending_req_list));
        assert(req->status == IN_CPL_P_LIST);
        QTAILQ_REMOVE(&pqp->cpl_pending_req_list, req, entry);
#if defined(__x86_64__)
        rc = femu_ring_enqueue(pqp->c2s_rq, (void **)&req, 1);
        assert(rc == 1);
#else
        QTAILQ_INSERT_TAIL(&pqp->c2s_list, req, entry);
#endif
        /* next time, we can continue handle next avail completion */
    }
}

int poll_pcq(struct leap *leap, struct nvme_qpair *pqp)
{
    struct nvme_completion pcqe;
    nvme_req *req;
    //nvme_req *tmp_req;
    //bool in_completer_list = false;
    int consumed = 0;
    //void *databuf;
    //int drain_cnt = 0;

    /* IMPORTANT FIX */
#if 0
    if (!leap_pcqe_valid(pqp, pqp->cq_head, pqp->cq_phase)) {
        //printf("Coperd,%s,leap_pcqe_valid failed,skip processing CQ\n", __func__);
        return 0;
    }
#endif

#if 0
    printf("Coperd,%s,begin handle a real pcqe\n", __func__);
#endif

    while (leap_read_pcqe(pqp, &pcqe)) {
        drain_rq(pqp, false);
#if 0
        drain_cnt = 0;
        while (QTAILQ_EMPTY(&pqp->completer_pending_req_list)) {
            drain_rq(pqp, false);
            drain_cnt++;
        }
        printf("Coperd,%s,drain_cnt=%d\n", __func__, drain_cnt);
#endif

        leap_handle_pcqe(leap, pqp, &pcqe);

        req = get_req_by_id(pqp, pcqe.cid);
#ifdef DEBUG_PQP
        printf("Coperd,%s,pqp[%d],get pCQE,req[%d],cmd.cid=%d,req->cid=%d\n",
                __func__, pqp->qid, req->id, req->cmd.c.cid, req->cid);
#endif
        req->cpl = pcqe;
        /* Restore cid from client */
        restore_cid(req, 1);

        /* USE SAME CID AS CLIENT, req->cid == pcqe.cid */
#if 0
        /* UGLY: for RDMA, have to restore original cmd cid from client: TODO */
        if (leap->transport == LEAP_RDMA) {
            req->cpl.cid = req->cid;
            //printf("Coperd,req[%d],cpl.cid=%d\n", req->id, req->cpl.cid);
        }
#endif

#if 0
        in_completer_list = false;
        QTAILQ_FOREACH(tmp_req, &pqp->completer_pending_req_list, entry) {
            if (tmp_req == req) {
                in_completer_list = true;
                break;
            }
        }
        if (in_completer_list == false) {
            /* need to do drain_rq() until we get this req, to optimize */
            printf("Coperd,BUG,%s,cpl-req not in completer_pending_req_list\n", __func__);
            drain_rq_until(pqp, false, req);
        }
#endif
        assert(req->status == IN_COMPLETER_P_LIST);
        QTAILQ_REMOVE(&pqp->completer_pending_req_list, req, entry);
        QTAILQ_INSERT_TAIL(&pqp->cpl_pending_req_list, req, entry);
        req->status = IN_CPL_P_LIST;

        consumed++;
        nr_processed++;
        if (nr_processed % 1000000 == 0) {
            printf("Coperd,%s,nr_processed=%" PRIu64 "\n", __func__, nr_processed);
        }
    }

    /* Coperd: batch CQ DB updates */
    if (consumed) {
        leap_ring_pcq_doorbell(pqp);
    }

    if (leap->transport == LEAP_TCP) {
        server_completer_process_cpls(leap, pqp);
    } else if (leap->transport == LEAP_RDMA) {
        server_completer_rdma_process_cpls(leap, pqp);
    } else {
        abort();
    }

    return 0;
}

int poll_pcqs(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct nvme_qpair *pqps = leap->pqps;
    struct nvme_qpair *pqp;
    int i;

    for (i = 1; i <= NR_DBVMS/*leap->nr_vqps*/; i++) {
        pqp = &pqps[i];
        poll_pcq(leap, pqp);
    }

    return 0;
}

void client_completer_return_io(struct nvme_qpair *vqp, nvme_req *req)
{
    struct nvme_completion *cqe = &req->cpl;

    leap_pcqe_to_vcqe(vqp, cqe);
    /* Restore cid from guest */
    restore_cid(req, 1);

#ifdef DEBUG_VQP
    printf("Coperd,%s,vCQ[%d],%d, ", __func__, vqp->qid, vqp->cq_tail);
    print_nvmecqe(cqe);
#endif

    memcpy((void *)&vqp->cqes[vqp->cq_tail], cqe, sizeof(*cqe));
    /* Coperd: TODO: how do we know if the vQP has been reset? */
    vcq_inc_tail(vqp);
    /* Coperd: ok, send virtual interrupt */
    vqp_inc_si(vqp);
}

/*
 * @ret: same as leap_nonblock_readv ret val, but also update iov status
 */
static int client_completer_recv_data(struct nvme_qpair *vqp, nvme_req *req)
{
    struct iovec *cur_iov;
    int cur_iovcnt = 0;
    int rc;

    //printf("Coperd,%s,req[%d] starts\n", __func__, req->id);

    /* continue transfer from status last time: ->cur_iov_idx, ->cur_iov_oft */
    assert(req->cur_iov_idx < req->iovcnt);
    cur_iov = (struct iovec *)&req->iov[req->cur_iov_idx];
    assert((unsigned)req->cur_iov_oft < cur_iov[0].iov_len);
    cur_iov[0].iov_base += req->cur_iov_oft;
    cur_iov[0].iov_len -= req->cur_iov_oft;
    //printf("Coperd,%s,%d,req[%d],iov[%d].len=%ld\n", __func__, __LINE__, req->id, req->cur_iov_idx, req->iov[req->cur_iov_idx].iov_len);
    assert(cur_iov[0].iov_len > 0 && cur_iov[0].iov_len <= 4096);
    cur_iovcnt = req->iovcnt - req->cur_iov_idx;
    assert(cur_iovcnt > 0);
    rc = leap_nonblock_readv(vqp->data_sockfd, cur_iov, cur_iovcnt);
    if (rc < 0) {
        return rc;
    }

    /* restore the state if no successful byte transfer */
    cur_iov[0].iov_base -= req->cur_iov_oft;
    cur_iov[0].iov_len += req->cur_iov_oft;

    //printf("Coperd,%s,before-advance-iov,req[%d],(%d,%d),cur_iov_idx:%d,cur_iov_oft:%d,cur_iov_len:%ld\n", __func__, req->id, req->len, req->data_bytes, req->cur_iov_idx, req->cur_iov_oft, req->iov[req->cur_iov_idx].iov_len);
    advance_req_iov_status(req, req->iov, rc);
    //printf("Coperd,%s,after-advance-iov,req[%d],(%d,%d)cur_iov_idx:%d,cur_iov_oft:%d,cur_iov_len:%ld\n", __func__, req->id, req->len, req->data_bytes, req->cur_iov_idx, req->cur_iov_oft, req->iov[req->cur_iov_idx].iov_len);
    //printf("Coperd,%s,req[%d] ends\n", __func__, req->id);
    return rc;
}

/*
 * @ret: same as leap_nonblock_read()
 */
static int client_completer_recv_cpl(struct nvme_qpair *vqp)
{
    void *cplbuf;
    int rem;
    int rc;

    assert(vqp->cmd_bytes < NVME_CPL_SZ);
    rem = NVME_CPL_SZ - vqp->cmd_bytes;
    cplbuf = (void *)((uintptr_t)&vqp->cpl + vqp->cmd_bytes);

    rc = leap_nonblock_read(vqp->cmd_sockfd, cplbuf, rem);
    if (rc < 0) {
        printf("Coperd,%s,%d,vqp[%d],socket failure,%d\n", __func__, __LINE__,
                vqp->qid, rc);
        abort();
    } else if (rc == 0) {
        return rc;
    }

    vqp->cmd_bytes += rc;
    assert(vqp->cmd_bytes <= NVME_CPL_SZ);
    return rc;
}

/* Get corresponding rbuf associated with a WR-CPL */
/* TODO: maybe better do batching here too */
nvme_req *leap_rdma_try_poll_cpl(struct leap *leap, struct nvme_qpair *vqp)
{
    struct rdma_context *rctx = vqp->rctx;
    nvme_req *rreq = NULL;
    struct ibv_wc wc;
    int rc;

    rc = ibv_poll_cq(rctx->cq, 1, &wc);
    if (rc < 0) {
        printf("Coperd,%s,ibv_poll_cq failed\n", __func__);
        abort();
    } else if (rc == 0) {
        /* Coperd: no cpl arrival, try next time */
        return NULL;
    }

    assert(rc == 1);
    if (wc.status != IBV_WC_SUCCESS) {
        printf("Coperd,%s,wc opcode: %d, RECV:%d,SEND:%d\n", __func__, wc.opcode,
                IBV_WC_RECV, IBV_WC_SEND);
        printf("Coperd,%s,Failed status %s (%d) for wr_id %d\n", __func__,
                ibv_wc_status_str(wc.status), wc.status, (int)wc.wr_id);
        abort();
    }

    switch (wc.opcode) {
    case IBV_WC_SEND:
        //printf("Coperd,%s,CQ recv\n", __func__);
        /* For now, do nothing, need to double check bytes_len */
        return NULL;

    case IBV_WC_RECV:
        // we are only interested in rbuf
        rreq = get_req_by_id(vqp, wc.wr_id);
        return rreq;

    default:
        abort();
    }
}

static void client_completer_rdma_process_pending_req_resp(struct leap *leap,
        struct nvme_qpair *vqp)
{
    int nprocessed = 0;
    nvme_req *req = NULL, *rreq = NULL;
    int cid;

    while (nprocessed++ < MAX_RDMA_BATCH_SZ) {
	    /* do we have pending cpl? */
	    drain_rq(vqp, false);

	    if (QTAILQ_EMPTY(&vqp->completer_pending_req_list)) {
		    return;
	    }

        /*
         * we are only using req->rbuf, the corresponding request associated
         * with data needs to be further identified by checking NVME_CPL
         */
        rreq = leap_rdma_try_poll_cpl(leap, vqp);
        if (!rreq) {
            return;
        }

        cid = ((struct nvme_completion *)rreq->rbuf)->cid;
        req = get_req_by_id(vqp, cid);

        /* copy completion back to corresponding req */
        memcpy(&req->cpl, rreq->rbuf, NVME_CPL_SZ);
        assert(req->cpl.cid == req->cmd.rw.cid);

#ifdef DEBUG_VQP
        printf("Coperd,%s,vqp[%d],recv-wr-cpl,req[%d], ", __func__, vqp->qid,
                req->id);
        print_nvmecmd(&req->cmd);
        print_nvmecqe(&req->cpl);
#endif

        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            // TODO TODO TODO
            // copy data back to req->iov which represents the original buffer
            // allocated by DBVM
            leap_client_copy_data_from_rbuf(req, rreq->rbuf);
            //assert(req->data_bytes == req->len);
            break;

        case NVME_CMD_WRITE:
            /* for write, once we recv the cpl, it's done */
            break;
        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,WTF,error\n");
            abort();
        }

        /* for RDMA, we need to restore cpl->cid here? */
        /* RDMA client will send NVMe command as is
         * RDMA server will guarantee the correct cid for CPL to CMD */
        //req->cpl.cid = req->cid;

#if 0
        bool in_completer_list = false;
        nvme_req *tmp_req;
        in_completer_list = false;
        QTAILQ_FOREACH(tmp_req, &vqp->completer_pending_req_list, entry) {
            if (tmp_req == req) {
                in_completer_list = true;
                break;
            }
        }
        if (in_completer_list == false) {
            /* need to do drain_rq() until we get this req, to optimize */
            drain_rq_until(vqp, false, req);
            printf("Coperd,%s,drain_rq_until req[%d]\n", __func__, req->id);
        }
#endif

        /* recycle the above rbuf */
        leap_client_post_recv(vqp->rctx, rreq);

	client_completer_return_io(vqp, req);

        assert(req->status == IN_COMPLETER_P_LIST);
        QTAILQ_REMOVE(&vqp->completer_pending_req_list, req, entry);
#if defined(__x86_64__)
        int rc;
        rc = femu_ring_enqueue(vqp->c2s_rq, (void **)&req, 1);
        if (rc != 1) {
            abort();
        }
#else
        QTAILQ_INSERT_TAIL(&vqp->c2s_list, req, entry);
#endif
    }
}


static void client_completer_azure_process_pending_req_resp(struct leap *leap,
							    struct nvme_qpair *vqp)
{
	int consumed = 0;
	nvme_req *req = NULL;
	struct nvme_qpair *pqp;
	struct nvme_completion pcqe;

	if ((leap->transport == LEAP_STRIPE) || (leap->transport == LEAP_RAID1))
		pqp = &leap->pqps[vqp->qid + NR_DBVMS];
	else {
		pqp = &leap->pqps[vqp->qid];
		if (leap->use_rdma_for_vqp) {
			/* Coperd: for this case, we actually only use pqp */
			vqp = pqp;
		}
	}

	while(1) {
		bool done = false;
		uint16_t status;
		uint16_t id;

		vqp->m_drive->dequeue_completion(done, status, id);

		if(done) {
			debug("one azure operation done: %u; status %u; id %u\n",
			      done, status, id );
		} else {
			break;
		}

		done = false;

		drain_rq(vqp, false);
		debug("Coperd,completer_azure_process, drained rq\n");

		/* we always use vqp->reqs for LocalSSD requests */
		req = get_req_by_id(vqp, id);

#ifdef DEBUG_PQP
		printf("Coperd,%s,pqp[%d],get pCQE,req[%d],cmd.cid=%d,req->cid=%d\n",
		       __func__, pqp->qid, req->id, req->cmd.c.cid, req->cid);
#endif
		/* Restore cid from client */
		restore_cid(req, 1);
		//req->cpl = pcqe;

		req->cpl.status = NVME_SUCCESS;
		req->cpl.cid = req->cmd.rw.cid;

		/* For vQP routing via RDMA */
		if (leap->use_rdma_for_vqp) {
			/* We need to send CPL back to WPT and it post completions for us */
			struct nvme_completion *cqe = &req->cpl;
			leap_pcqe_to_vcqe(pqp, cqe);

#ifdef DEBUG_VQP
			printf("Coperd,%s,%d,vCQ[%d],%d, ", __func__, __LINE__, pqp->qid,
			       pqp->cq_tail);
			print_nvmecqe(cqe);
#endif

			/* Coperd: TODO: how do we know if the vQP has been reset? */
			vcq_inc_tail(pqp);
			/* Coperd: ok, send virtual interrupt */
			//vqp_inc_si(vqp);

			memcpy(req->cplbuf, cqe, NVME_CPL_SZ);

			// copy data. right now only able to ship 4K of data
			// TODO: this one not necessary as we can register the ht with rdma, leave some
			// space for cpl in front of each lba, and pass that to Azure library when
			// feching new lbas. only cpl needs to be copied into the ht entry. 
			//memcpy(req->cplbuf + NVME_CPL_SZ, req->iov[0].iov_base, RBUF_SIZE -
			//       NVME_CPL_SZ - NVME_CMD_SZ);

#ifdef ABC			
			abc_set_valid(req->cmd.rw.slba);
#endif
			/* Coperd: send CPL in req->cplbuf back to WPT for cpl handling */

			leap_client_post_send2(pqp->rctx, req);

			debug("client_completer_azure: sent reply back to driver\n");
			/* Do we still need to maintain vCQ status here?? */
		} else {
			/*
			 * Default path: vQP sharing via shared memory, socp directly post
			 * completion to guest vQP
			 */
			client_completer_return_io(vqp, req);
		}

#if 0
		assert(req->status == IN_COMPLETER_P_LIST);
		QTAILQ_REMOVE(&pqp->completer_pending_req_list, req, entry);
		QTAILQ_INSERT_TAIL(&pqp->cpl_pending_req_list, req, entry);
		req->status = IN_CPL_P_LIST;
#endif

		assert(req->status == IN_COMPLETER_P_LIST);
		QTAILQ_REMOVE(&vqp->completer_pending_req_list, req, entry);

#if defined(__x86_64__)
		int rc;
		rc = femu_ring_enqueue(vqp->c2s_rq, (void **)&req, 1);
		if (rc != 1) {
			abort();
		}
#else
		QTAILQ_INSERT_TAIL(&vqp->c2s_list, req, entry);
#endif

		nr_processed++;
		if (nr_processed % 100000 == 0) {
			printf("Coperd,%s,nr_processed=%" PRIu64 "\n",
			       __func__, nr_processed);
		}
	}
}


static void client_completer_pcie_process_pending_req_resp(struct leap *leap,
        struct nvme_qpair *vqp)
{
    int consumed = 0;
    nvme_req *req = NULL;
    struct nvme_qpair *pqp;
    struct nvme_completion pcqe;

    if ((leap->transport == LEAP_STRIPE) || (leap->transport == LEAP_RAID1))
	    pqp = &leap->pqps[vqp->qid + NR_DBVMS];
    else {
	    pqp = &leap->pqps[vqp->qid];
	    if (leap->use_rdma_for_vqp) {
		    /* Coperd: for this case, we actually only use pqp */
		    vqp = pqp;
	    }
    }

    while (leap_read_pcqe(pqp, &pcqe)) {
        if (leap->transport != LEAP_RAID1) {
#ifdef DEBUG_PQP
            printf("Coperd,completer_pcie_process, draining rq\n");
#endif
            drain_rq(vqp, false);
        }
        leap_handle_pcqe(leap, pqp, &pcqe);

        if(leap->transport == LEAP_RAID1) {
            consumed++;
            continue;
        }

        /* we always use vqp->reqs for LocalSSD requests */
        req = get_req_by_id(vqp, pcqe.cid);
#ifdef DEBUG_PQP
        printf("Coperd,%s,pqp[%d],get pCQE,req[%d],cmd.c.cid=%d,cmd.rw.cid=%d,req->cid=%d\n",
	       __func__, pqp->qid, req->id, req->cmd.c.cid, req->cmd.rw.cid, req->cid);
#endif
        /* Restore cid from client */
        restore_cid(req, 1);
        req->cpl = pcqe;

        /* For vQP routing via RDMA */
        if (leap->use_rdma_for_vqp) {
            /* We need to send CPL back to WPT and it post completions for us */
            struct nvme_completion *cqe = &req->cpl;
            leap_pcqe_to_vcqe(pqp, cqe);

#ifdef DEBUG_VQP
            printf("Coperd,%s,%d,vCQ[%d],%d, ", __func__, __LINE__, pqp->qid,
                    pqp->cq_tail);
            print_nvmecqe(cqe);
#endif

            /* Coperd: TODO: how do we know if the vQP has been reset? */
            //vcq_inc_tail(pqp);
            /* Coperd: ok, send virtual interrupt */
            //vqp_inc_si(vqp);

            memcpy(req->cplbuf, cqe, NVME_CPL_SZ);

            /* Coperd: send CPL in req->cplbuf back to WPT for cpl handling */
            leap_client_post_send2(pqp->rctx, req);

            /* Do we still need to maintain vCQ status here?? */
        } else {
            /*
             * Default path: vQP sharing via shared memory, socp directly post
             * completion to guest vQP
             */
            client_completer_return_io(vqp, req);
        }

#if 0
        assert(req->status == IN_COMPLETER_P_LIST);
        QTAILQ_REMOVE(&pqp->completer_pending_req_list, req, entry);
        QTAILQ_INSERT_TAIL(&pqp->cpl_pending_req_list, req, entry);
        req->status = IN_CPL_P_LIST;
#endif

        assert(req->status == IN_COMPLETER_P_LIST);

        QTAILQ_REMOVE(&vqp->completer_pending_req_list, req, entry);

#if defined(__x86_64__)
        int rc;
        rc = femu_ring_enqueue(vqp->c2s_rq, (void **)&req, 1);
        if (rc != 1) {
            abort();
        }
#else
        QTAILQ_INSERT_TAIL(&vqp->c2s_list, req, entry);
#endif

        consumed++;
        nr_processed++;
        if (nr_processed % 100000 == 0) {
            printf("Coperd,%s,nr_processed=%" PRIu64 "\n", __func__, nr_processed);
        }
    }

    /* Coperd: batch CQ DB updates */
    if (consumed) {
        leap_ring_pcq_doorbell(pqp);
    }
}

static void client_completer_tcp_process_pending_req_resp(struct leap *leap,
        struct nvme_qpair *vqp)
{
    int nprocessed = 0;
    nvme_req *req = NULL;
    int rc;

    struct nvme_qpair *pqp;
    struct nvme_completion pcqe;

    if ((leap->transport == LEAP_STRIPE) || (leap->transport == LEAP_RAID1))
	    pqp = &leap->pqps[vqp->qid + NR_DBVMS];
    else {
	    pqp = &leap->pqps[vqp->qid];
	    if (leap->use_rdma_for_vqp) {
		    /* Coperd: for this case, we actually only use pqp */
		    vqp = pqp;
	    }
    }

    while (nprocessed++ < MAX_BATCH_SZ) {
        /* do we have pending cpl? */
        drain_rq(vqp, false);

        if (QTAILQ_EMPTY(&vqp->completer_pending_req_list)) {
            return;
        }
        /* wait until completion (16bytes) is successfully received */
        if (vqp->cmd_bytes < NVME_CPL_SZ) {
            rc = client_completer_recv_cpl(vqp);
            if (rc < 0) {
                printf("Coperd,%s,%d,vqp[%d],socket failure,%d\n", __func__,
                        __LINE__, vqp->qid, rc);
                abort();
            } else if (rc == 0) {
                return;
            }
        }

        /* do we have a complete cpl now? */
        if (vqp->cmd_bytes < NVME_CPL_SZ) {
            /* bad luck, let others run */
            return;
        }

	debug("[TCP] Received CPL from server\n");

        /* completed cpl received */
        assert(vqp->cmd_bytes == NVME_CPL_SZ);
        if (!vqp->cur_recv_req) {
            req = get_req_by_id(vqp, vqp->cpl.cid);
            req->cpl = vqp->cpl;
            vqp->cur_recv_req = req;
#ifdef DEBUG_VQP
            printf("Coperd,%s,vqp[%d],recv-cpl-from-server: ", __func__, vqp->qid);
            print_nvmecqe(&req->cpl);
#endif
        }
        assert(vqp->cur_recv_req);
        req = vqp->cur_recv_req;

        switch (req->cmd.c.opcode) {
        case NVME_CMD_READ:
            rc = client_completer_recv_data(vqp, req);
            if (rc < 0) {
                printf("Coperd,%s,%d,vqp[%d],socket failure,%d\n", __func__,
                        __LINE__, vqp->qid, rc);
                abort();
            } else if (rc == 0) {
                return;
            }

            if (req->data_bytes < req->len)
                return;

            assert(req->data_bytes == req->len);

	    debug("[TCP] Received %u bytes of data from server\n", req->data_bytes);

            break;

        case NVME_CMD_WRITE:
            /* for write, once we recv the cpl, it's done */
#ifdef DEBUG_VQP
            printf("Coperd,%s,vqp[%d],recv-wr-cpl,req[%d], ", __func__, vqp->qid,
                    req->id);
            print_nvmecmd(&req->cmd);
            print_nvmecqe(&req->cpl);
#endif
            break;
        case NVM_OP_PREAD:
        case NVM_OP_PWRITE:
        case NVM_OP_ERASE:
        default:
            printf("Coperd,WTF,error\n");
            abort();
        }


	/* For vQP routing via RDMA */
	if (leap->use_rdma_for_vqp) {
#ifdef DEBUG_VQP
		printf("RECEIVED RESPONSE: Sending CPL back to the client\n");
#endif

		/* We need to send CPL back to WPT and it post completions for us */
		struct nvme_completion *cqe = &req->cpl;
		leap_pcqe_to_vcqe(pqp, cqe);

#ifdef DEBUG_VQP
		printf("Coperd,%s,%d,vCQ[%d],%d, ", __func__, __LINE__, pqp->qid,
		       pqp->cq_tail);
		print_nvmecqe(cqe);
#endif

		/* Coperd: TODO: how do we know if the vQP has been reset? */
		vcq_inc_tail(pqp);
		/* Coperd: ok, send virtual interrupt */
		//vqp_inc_si(vqp);

		memcpy(req->cplbuf, cqe, NVME_CPL_SZ);

		// copy data. right now only able to ship 4K of data
		// TODO: this one not necessary as we can register the ht with rdma, leave some
		// space for cpl in front of each lba, and pass that to Azure library when
		// feching new lbas. only cpl needs to be copied into the ht entry. 
		//memcpy(req->cplbuf + NVME_CPL_SZ, req->iov[0].iov_base, RBUF_SIZE -
		//       NVME_CPL_SZ - NVME_CMD_SZ);

#ifdef ABC			
		abc_set_valid(req->cmd.rw.slba);
#endif
		/* Coperd: send CPL in req->cplbuf back to WPT for cpl handling */

		leap_client_post_send2(pqp->rctx, req);

		debug("client_completer_azure: sent reply back to driver\n");
		/* Do we still need to maintain vCQ status here?? */
	} else {
		/*
		 * Default path: vQP sharing via shared memory, socp directly post
		 * completion to guest vQP
		 */
		client_completer_return_io(vqp, req);
	}

	//client_completer_return_io(vqp, req);

#if 0
        bool in_completer_list = false;
        nvme_req *tmp_req;
        in_completer_list = false;
        QTAILQ_FOREACH(tmp_req, &vqp->completer_pending_req_list, entry) {
            if (tmp_req == req) {
                in_completer_list = true;
                break;
            }
        }
        if (in_completer_list == false) {
            /* need to do drain_rq() until we get this req, to optimize */
            drain_rq_until(vqp, false, req);
            printf("Coperd,%s,drain_rq_until req[%d]\n", __func__, req->id);
        }
#endif
        assert(req->status == IN_COMPLETER_P_LIST);
        QTAILQ_REMOVE(&vqp->completer_pending_req_list, req, entry);
#if defined(__x86_64__)
        rc = femu_ring_enqueue(vqp->c2s_rq, (void **)&req, 1);
        assert(rc == 1);
#else
        QTAILQ_INSERT_TAIL(&vqp->c2s_list, req, entry);
#endif

        /* reset req->cpl, so we can trigger new completion in next iter */
        memset(&vqp->cpl, 0, NVME_CPL_SZ);
        vqp->cmd_bytes = 0;
        vqp->cur_recv_req = NULL;
        req = NULL;
    }
}

static void poll_resp(struct leap *leap)
{
    struct nvme_qpair *vqp;
    int i;

    for (i = 1; i <= NR_DBVMS/*leap->nr_vqps*/; i++) {
        vqp = &leap->vqps[i];
        if (leap->transport == LEAP_PCIE) {
            client_completer_pcie_process_pending_req_resp(leap, vqp);
        } else if (leap->transport == LEAP_TCP) {
            client_completer_tcp_process_pending_req_resp(leap, vqp);
        } else if (leap->transport == LEAP_RDMA) {
            client_completer_rdma_process_pending_req_resp(leap, vqp);
        } else if((leap->transport == LEAP_STRIPE) || (leap->transport == LEAP_RAID1)) {
            client_completer_pcie_process_pending_req_resp(leap,vqp);
            client_completer_rdma_process_pending_req_resp(leap,vqp);
        } else if(leap->transport == LEAP_AZURE) {
		client_completer_azure_process_pending_req_resp(leap, vqp);
	} else {
		abort();
        }
    }
}

void *client_poller_ts(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct nvme_qpair *vqp;
    int i;

    /* For vQP routing */
    if ((leap->transport == LEAP_PCIE && leap->use_rdma_for_vqp) ||
	(leap->transport == LEAP_AZURE && leap->use_rdma_for_vqp) ||
	(leap->transport == LEAP_TCP && leap->use_rdma_for_vqp)) {
        for (i = 1; i <= NR_DBVMS; i++) {
            /* THIS IS CORRECT, vqp actually is pqp */
            vqp = &leap->pqps[i];
            assert(vqp->qid == i);
            leap_client_post_initial_recvs2(leap, vqp);
        }
    }

    if ((leap->transport == LEAP_RDMA) || (leap->transport == LEAP_STRIPE) ||
            (leap->transport == LEAP_RAID1)) {
        for (i = 1; i <= NR_DBVMS; i++) {
            vqp = &leap->vqps[i];
            assert(vqp->qid == i);
            leap_client_post_initial_recvs(leap, vqp);
        }
    }

    while (1) {
        /* poll vsq for new submissions and send them to server */
        poll_vsqs(leap);
        /* poll resps from server and send them back to guest */
#ifndef CORE_IOPS_TEST
        poll_resp(leap);
#endif
    }

    return NULL;
}

void *client_submitter_ts(void *arg)
{
    struct leap *leap = (struct leap *)arg;

    while (1) {
        /* poll vsq for new submissions and send them to server */
        poll_vsqs(leap);
    }

    return NULL;
}

/* Coperd: poll resp cpl & data from network and then handle vQP completion */
void *client_completer_ts(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct nvme_qpair *vqp; // = &vqps[pq->qid];
    int i;

    while (1) {
        for (i = 1; i <= NR_DBVMS/*leap->nr_vqps*/; i++) {
            vqp = &leap->vqps[i];
            client_completer_tcp_process_pending_req_resp(leap, vqp);
        }
    }

    return NULL;
}

void *server_completer_ts(void *arg)
{
    struct leap *leap = (struct leap *)arg;

    while (1) {
        poll_pcqs(leap);
    }

    return NULL;
}

pthread_t *create_worker(void *(*fn)(void *), void *arg)
{
    int ret;

    pthread_t *worker = (pthread_t *)malloc(sizeof(pthread_t));
    if (!worker) {
        return NULL;
    }

    ret = pthread_create(worker, NULL, fn, arg);
    if (ret) {
        return NULL;
    }

    return worker;
}

/*
 * Server submitter: check cmd_sockfd for incoming NVMe commands, once we recv
 * one, start recv necessary data if any, then we go ahead and process this IO
 */
void *server_submitter_ts(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct nvme_qpair *pqp;
    int i;

    while (1) {
        for (i = 1; i < 2/*vqp->nr_vqps*/; i++) {
            pqp = &leap->pqps[i];
            if (leap->transport == LEAP_TCP) {
                server_submitter_process_incoming_reqs(pqp);
            } else if (leap->transport == LEAP_RDMA) {
                server_submitter_rdma_process_incoming_reqs(pqp);
            } else {
                abort();
            }
        }
    }

    return NULL;
}

void *server_poller_ts(void *arg)
{
    struct leap *leap = (struct leap *)arg;
    struct nvme_qpair *pqp;
    int i;

    if (leap->transport == LEAP_RDMA) {
        for (i = 1; i <= NR_DBVMS; i++) {
            pqp = &leap->pqps[i];
            assert(pqp->qid == i);
            leap_server_post_initial_recvs(leap, pqp);
        }
    }

    while (1) {
        /* submitter: handle incoming submissions */
        for (i = 1; i <= NR_DBVMS/*vqp->nr_vqps*/; i++) {
            pqp = &leap->pqps[i];
            if (leap->transport == LEAP_PCIE) {
                printf("Coperd,%s,%d,impossible!\n", __func__, __LINE__);
                abort();
            } else if (leap->transport == LEAP_TCP) {
                server_submitter_process_incoming_reqs(pqp);
            } else if (leap->transport == LEAP_RDMA) {
                server_submitter_rdma_process_incoming_reqs(pqp);
            } else {
                abort();
            }
        }

        /* completer: handle cpls */
        poll_pcqs(leap);
    }

    return NULL;
}


#ifdef PSCHEDULE
// init priority scheduling
void sched_init(struct leap *leap)
{
	leap->pr_cnt[0].current = 0;
	leap->pr_cnt[0].max = PR0;

	leap->pr_cnt[1].current = 0;
	leap->pr_cnt[1].max = PR1;
}
#endif


/* single threaded client or server */
int leap_init_poller(struct leap *leap)
{
#ifdef PSCHEDULE
	sched_init(leap);
#endif

#ifdef ABC
	// allocate 3MB for Azure Blob Cache
	abc_init(3 * 1024 * 1024);
#endif

    if (leap->role == SOCK_SERVER) {
	    leap->submitter = create_worker(server_poller_ts, leap);
    } else if (leap->role == SOCK_CLIENT) {
	    leap->submitter = create_worker(client_poller_ts, leap);
    } else if(leap->role == SOCK_AZURE) {
	    leap->submitter = create_worker(client_poller_ts, leap);
    }

    if (!leap->submitter) {
	    return -1;
    }

    return 0;
}

int leap_init_submitter(struct leap *leap)
{
    if (leap->role == SOCK_SERVER) {
        leap->submitter = create_worker(server_submitter_ts, leap);
    } else if (leap->role == SOCK_CLIENT) {
        leap->submitter = create_worker(client_submitter_ts, leap);
    } else {
        return -1;
    }

    if (!leap->submitter) {
        return -1;
    }

    return 0;
}

int leap_init_completer(struct leap *leap)
{
    if (leap->role == SOCK_SERVER) {
        leap->completer = create_worker(server_completer_ts, leap);
    } else if (leap->role == SOCK_CLIENT) {
        leap->completer = create_worker(client_completer_ts, leap);
    } else {
        return -1;
    }

    if (!leap->completer) {
        return -1;
    }

    return 0;
}

int leap_wait_for_end(struct leap *leap)
{
    pthread_join(*leap->submitter, NULL);
#ifdef USE_LEAP_THREADS
    pthread_join(*leap->completer, NULL);
#endif

    printf("\nLeap: you know this day will come sooner or later ... ends\n\n");

    return 0;
}

int leap_init_leap(struct leap *leap)
{
    int ret;
    int i;
    int nfds;

    /* Must come before any get_host_phys_addr_base() call */
#if defined(__x86_64__)
    leap_map_host_as(leap);
#endif

    //leap->host_as_base_va = get_host_phys_addr_base(leap);
#if 0
    for (i = 0; i < 1ULL * 1024 * 1024; i++) {
        printf("Coperd,i=%d\n", i);
        *(volatile char *)(&((volatile char *)leap->host_as_base_va)[i]) = ((char *)leap->host_as_base_va)[i];
    }
    printf("Coperd,rewrite done ...\n");
#endif

    leap->nr_vqps = MAX_NR_VQPS;
    leap->vqps = (struct nvme_qpair *)malloc(sizeof(struct nvme_qpair) *
            (leap->nr_vqps + 1));
    if (!leap->vqps) {
        ret = errno;
        return -1;
    }
    leap->nr_pqps = NR_PQP;
    leap->pqps = (struct nvme_qpair *)malloc(sizeof(struct nvme_qpair) *
            (leap->nr_pqps + 1));
    if (!leap->pqps) {
        ret = errno;
        goto err_malloc_pqps;
    }
    memset(leap->vqps, 0, sizeof(struct nvme_qpair) * (leap->nr_vqps + 1));
    memset(leap->pqps, 0, sizeof(struct nvme_qpair) * (leap->nr_pqps + 1));
    printf("Coperd,%s,inited leap->vqps and leap->pqps structure\n", __func__);

    nfds = (leap->nr_vqps < leap->nr_pqps) ? leap->nr_vqps : leap->nr_pqps;
    nfds *= 2;

    leap->sockfds = (int *)malloc(sizeof(int) * nfds);
    leap->nfds = nfds;
    assert(leap->sockfds);
    for (i = 0; i < nfds; i++) {
        leap->sockfds[i] = -1;
    }

    leap->pgsz = getpagesize();
    assert(leap->pgsz == 4096);

#if !defined(__x86_64__)
    leap->use_rdma_for_vqp = RDMA_VQP_SHARING;
#endif

#ifdef SNAPSHOTS
    leap->log = new snapshot_nvme::snvme_pmem();
#endif

    return 0;

err_malloc_pqps:
    free(leap->vqps);
    return ret;
}

void leap_free_leap(struct leap *leap)
{

    free(leap->vqps);
    free(leap->pqps);

    free(leap->submitter);
    free(leap->completer);

    free(leap);
}

void do_test(struct leap *leap)
{
    struct nvme_qpair *vqps = leap->vqps;
    struct nvme_qpair *pqps = leap->pqps;

    TEST_VSQ(vqps, MAX_NR_VQPS);
    TEST_VCQ(vqps, MAX_NR_VQPS);
    exit(1);

    TEST_VSQ(pqps, NR_PQP);
    TEST_VCQ(pqps, NR_PQP);
    exit(1);

    sleep(1);
    printf("Coperd,%s,begin poll_vsqs()\n", __func__);
    poll_vsqs(leap);
    printf("Coperd,%s,end poll_vsqs()\n", __func__);
}

static void usage()
{
    printf("\nUsage:\n"
            "    RDMASSD:\n"
            "      - Server: ./socp server rdma addr port\n"
            "      - Client: ./socp client rdma addr port\n"
            "    LocalSSD:\n"
            "                ./socp client pcie\n");
    exit(1);
}

#define SERVER_MSG "msg-from_quantum-leap-server"
#define CLIENT_MSG "msg-from-quantum-leap-client"

static int leap_verify_tcp_client(struct leap *leap)
{
    const char *cmsg = (char *)CLIENT_MSG;
    char crecvbuf[MAX_TMPBUF];
    char csendbuf[MAX_TMPBUF];
    int nsend_bytes = 0, nrecv_bytes = 0, rem = MAX_TMPBUF;
    int rc;

    memset(csendbuf, 0, sizeof(csendbuf));
    strcpy(csendbuf, cmsg);
retry_send:
    while (nsend_bytes != MAX_TMPBUF) {
        rc = write(leap->sockfds[0], &csendbuf[nsend_bytes], rem);
        if (rc == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                goto retry_send;
            }
        } else if (rc == 0) {
            return -1;
        } else if (rc > 0) {
            nsend_bytes += rc;
            rem -= nsend_bytes;
        }
    }
    printf("Coperd,client sends out msg(%d bytes) to server\n", nsend_bytes);

    memset(crecvbuf, 0, sizeof(crecvbuf));
    rem = MAX_TMPBUF;
retry_recv:
    while (nrecv_bytes != MAX_TMPBUF) {
        rc = read(leap->sockfds[0], &crecvbuf[nrecv_bytes], rem);
        if (rc == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                goto retry_recv;
            }
        } else if (rc == 0) {
            return -1;
        } else if (rc > 0) {
            nrecv_bytes += rc;
            rem -= nrecv_bytes;
        }
    }

    return !!strcmp(crecvbuf, (char *)SERVER_MSG);
}

static int leap_verify_tcp_server(struct leap *leap)
{
    const char *smsg = (char *)SERVER_MSG;
    char srecvbuf[MAX_TMPBUF];
    char ssendbuf[MAX_TMPBUF];
    int nsend_bytes = 0, nrecv_bytes = 0, rem = MAX_TMPBUF;
    int rc;

    memset(srecvbuf, 0, sizeof(srecvbuf));
retry_recv:
    while (nrecv_bytes != MAX_TMPBUF) {
        rc = read(leap->sockfds[0], &srecvbuf[nrecv_bytes], rem);
        if (rc == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                goto retry_recv;
            }
        } else if (rc == 0) {
            return -1;
        } else if (rc > 0) {
            nrecv_bytes += rc;
            rem -= nrecv_bytes;
        }
    }
    if (strcmp(srecvbuf, (char *)CLIENT_MSG) != 0) {
        return -1;
    }

    memset(ssendbuf, 0, sizeof(ssendbuf));
    strcpy(ssendbuf, smsg);
    rem = MAX_TMPBUF;
retry_send:
    while (nsend_bytes != MAX_TMPBUF) {
        rc = write(leap->sockfds[0], &ssendbuf[nsend_bytes], rem);
        if (rc == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                goto retry_send;
            }
        } else if (rc == 0) {
            return -1;
        } else if (rc > 0) {
            nsend_bytes += rc;
            rem -= nsend_bytes;
        }
    }
    printf("Coperd,server sends out msg(%d bytes) to client\n", nsend_bytes);

    return 0;
}

/*
 * make sure both sockets associated with each qpair can send/recv data
 * bidirectionally, i.e.,
 *  - cmd-socket: client(msg) <-> server
 *  - data-socket: server(msg) <-> client
 * role: 0-> client, 1->server
 */
static int leap_verify_tcp_endpoint(struct leap *leap)
{
    if (leap->role == SOCK_CLIENT) {
        return leap_verify_tcp_client(leap);
    } else if (leap->role == SOCK_SERVER) {
        return leap_verify_tcp_server(leap);
    }

    return -1;
}

static int leap_setup_tcp_endpoint(struct leap *leap, int argc, char **argv)
{
    char *sip = (char *)DEFAULT_IP;
    int port = DEFAULT_PORT;
    int rc;
    int i;

    sip = leap->ip;
    port = leap->port;

    if (leap->role == SOCK_CLIENT) {
        /* client endpoint handling */
        for (i = 0; i < leap->nfds; i++) {
            leap->sockfds[i] = leap_sock_client(sip, port);
            assert(leap->sockfds[i] > 0);
            printf("Coperd,leap->sockfds[%d]=%d\n", i, leap->sockfds[i]);
        }
    } else if (leap->role == SOCK_SERVER) {
        /* server endpoint handling */
        printf("Coperd,server at [%s:%d]\n", sip, port);
        int tfd = leap_sock_server(sip, port);
        int sfd = -1;
        int cnt = 0;
        /* Coperd: busy loop until clients come */
        while (sfd < 0 && cnt != leap->nfds) {
            sfd = leap_sock_accept(tfd);
            if (sfd > 0) {
                leap->sockfds[cnt] = sfd;
                printf("Coperd,leap->sockfds[%d]=%d\n", cnt, leap->sockfds[cnt]);
                cnt++;
                sfd = -1;
            }
        }
        printf("Coperd, server fds[0]:%d,fds[1]:%d\n", leap->sockfds[0], leap->sockfds[1]);
    } else {
        usage();
    }

    //printf("Coperd,cmd_sockfd:%d,data_sockfd:%d\n", leap->cmd_sockfd, leap->data_sockfd);

    rc = leap_verify_tcp_endpoint(leap);
    if (rc != 0) {
        printf("Coperd,quantumleap TCP channel verification failed\n");
        return -1;
    }

    return 0;
}

static int rdma_server_init(struct leap *leap)
{
    struct sockaddr_in addr;
    struct rdma_context *rctx;
    //int optval = 16;
    //int r;
    int i;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr((char *)leap->ip);

    printf("Init RDMA server at [%s:%d]...\n", (char *)leap->ip, leap->port);
    TEST_Z(leap->ec = rdma_create_event_channel());

    for (i = 0; i < NR_DBVMS; i++) {
        addr.sin_port = htons(leap->port + i);
        rctx = &leap->rctx[i];
        TEST_NZ(rdma_create_id(leap->ec, &rctx->id, rctx, RDMA_PS_TCP));
        printf("Coperd,%s,rctx[%d]->id=%p\n", __func__, i, rctx->id);
#if 0
        r = rdma_set_option(rctx->id, RDMA_OPTION_ID, RDMA_OPTION_ID_REUSEADDR,
                (void *)&optval, sizeof(optval));
        assert(r == 0);
#endif
        TEST_NZ(rdma_bind_addr(rctx->id, (struct sockaddr *)&addr));
        TEST_NZ(rdma_listen(rctx->id, 10)); /* backlog=10 is arbitrary */
        printf("Coperd,rdma_listen rctx(%p) done ..\n", rctx);
    }

    TEST_NZ(pthread_create(&leap->cm_event_ts, NULL, server_cm_event_ts, leap));
    printf("Server listening for connections...\n");

    if (pthread_join(leap->cm_event_ts, NULL)) {
        printf("Server cm_event_thread done...\n");
    }

    return 0;
}

/* Coperd: start a RDMA server at socp-client for routing vQP commands */
static int rdma_server_init_pcie(struct leap *leap)
{
    struct sockaddr_in addr;
    struct rdma_context *rctx;
    //int optval = 16;
    //int r;
    int i;

    addr.sin_family = AF_INET;
    if(leap->transport == LEAP_TCP) {
	    addr.sin_addr.s_addr = inet_addr((char *)leap->rdma_ip);
    } else {
	    addr.sin_addr.s_addr = inet_addr((char *)leap->ip);
    }

    assert(leap->ip && leap->port);
    if(leap->transport == LEAP_TCP) {
	    printf("QP-PCIe: Init RDMA server at [%s:%d]...\n", (char *)leap->rdma_ip, leap->rdma_port);
    } else {
	    printf("QP-PCIe: Init RDMA server at [%s:%d]...\n", (char *)leap->ip, leap->port);
    }
    TEST_Z(leap->ec2 = rdma_create_event_channel());

    for (i = 0; i < NR_DBVMS; i++) {
	    if(leap->transport == LEAP_TCP) {
		    addr.sin_port = htons(leap->rdma_port + i);
	    } else {
		    addr.sin_port = htons(leap->port + i);
	    }

        rctx = &leap->rctx2[i];
        TEST_NZ(rdma_create_id(leap->ec2, &rctx->id, rctx, RDMA_PS_TCP));
        printf("QP-PCIe,%s,rctx[%d]->id=%p\n", __func__, i, rctx->id);
#if 0
        r = rdma_set_option(rctx->id, RDMA_OPTION_ID, RDMA_OPTION_ID_REUSEADDR,
                (void *)&optval, sizeof(optval));
        assert(r == 0);
#endif
        TEST_NZ(rdma_bind_addr(rctx->id, (struct sockaddr *)&addr));
        TEST_NZ(rdma_listen(rctx->id, 10)); /* backlog=10 is arbitrary */
        printf("QP-PCIe,rdma_listen rctx(%p) done ..\n", rctx);
    }

    TEST_NZ(pthread_create(&leap->cm_event_ts2, NULL, server_cm_event_ts2, leap));
    printf("QP-PCIe,Server listening for connections...\n");

    if (pthread_join(leap->cm_event_ts2, NULL)) {
        printf("QP-PCIe,server cm_event_thread done...\n");
    }

    return 0;
}

static int rdma_client_init(struct leap *leap)
{
    struct rdma_context *rctx;
    char pstr[64];
    int i;

    printf("Init RDMA client to [%s:%d]...\n", (char *)leap->ip, leap->port);
    // use one event channel for all RDMA QPs
    TEST_Z(leap->ec = rdma_create_event_channel());

    for (i = 0; i < NR_DBVMS; i++) {
        struct addrinfo *addr;
        rctx = &leap->rctx[i];
        printf("Coperd,rctx[%d]=%p\n", i, rctx);
        rctx->rid = i + 10;
        rctx->ec = leap->ec;

        memset(pstr, 0, 64);
        sprintf(pstr, "%d", leap->port + i);
        TEST_NZ(getaddrinfo(leap->ip, pstr, NULL, &addr));

        TEST_NZ(rdma_create_id(leap->ec, &rctx->id, rctx, RDMA_PS_TCP));
        printf("Coperd,%s,rdma_create_id, initial rctx[%d]->id=%p\n", __func__, i, rctx->id);
        TEST_NZ(rdma_resolve_addr(rctx->id, NULL, addr->ai_addr, TIMEOUT_IN_MS));
    }

    TEST_NZ(pthread_create(&leap->cm_event_ts, NULL, client_cm_event_ts, leap));

    if (pthread_join(leap->cm_event_ts, NULL)) {
        printf("Client cm_event_thread done...\n");
    }

    //freeaddrinfo(addr);

    return 0;
}

static int leap_setup_rdma_endpoint(struct leap *leap)
{
    struct rdma_context *rctx;
    int i;

    leap->rctx = (struct rdma_context *)calloc(NR_DBVMS,
					       sizeof(struct rdma_context));
    assert(leap->rctx);

    for (i = 0; i < NR_DBVMS; i++) {
        rctx = &leap->rctx[i];
        assert(rctx);
        rctx->host_as_base_va = leap->host_as_base_va;
        rctx->leap = leap;
    }

    if (leap->role == SOCK_SERVER) {
        rdma_server_init(leap);
    } else if (leap->role == SOCK_CLIENT) {
        rdma_client_init(leap);
    } else {
        printf("Coperd,unknown role type:%d\n", leap->role);
        exit(EXIT_FAILURE);
    }

    /* Associate NVMe QP with RDMA QP context */
    for (i = 1; i <= NR_DBVMS; i++) {
        struct nvme_qpair *qp;
        if (leap->role == SOCK_SERVER) {
            qp = &leap->pqps[i];
            qp->rctx = &leap->rctx[i - 1];
        } else if (leap->role == SOCK_CLIENT) {
            qp = &leap->vqps[i];
            qp->rctx = &leap->rctx[i - 1];
        }
    }

    return 0;
}

/* Coperd: setup RDMA server endpoint at socp client side for routing vQP */
static int leap_setup_rdma_endpoint_pcie(struct leap *leap)
{
    struct rdma_context *rctx;
    int i;

    leap->rctx2 = (struct rdma_context *)calloc(NR_DBVMS,
            sizeof(struct rdma_context));
    assert(leap->rctx2);

    for (i = 0; i < NR_DBVMS; i++) {
        rctx = &leap->rctx2[i];
        assert(rctx);
        rctx->host_as_base_va = leap->host_as_base_va;
        rctx->leap = leap;
        rctx->rid = i;
    }

    assert((leap->role == SOCK_CLIENT) || (leap->role == SOCK_AZURE));
    rdma_server_init_pcie(leap);

    printf("QP-PCIe,RDMA channel established for sharing vQP from DBVM\n");

    return 0;
}

static int leap_parse_args(struct leap *leap, int argc, char **argv)
{
    assert(argc >= 3);
    /* Coperd: assign leap->role at earliest convenience */
    if (strcmp(argv[1], "client") == 0) {
        leap->role = SOCK_CLIENT;
        printf("Coperd,Role:%s\n", "Client");
    } else if (strcmp(argv[1], "server") == 0) {
        leap->role = SOCK_SERVER;
        printf("Coperd,Role:%s\n", "Server");
    } else if(strcmp(argv[1], "azure") == 0) {
	    leap->role = SOCK_AZURE;
	    printf("Coperd,Role:%s\n", "Azure");
    } else {
        printf("\nError: argv[1] must be \"server\" or \"client\"\n\n");
        usage();
    }

    if (strcmp(argv[2], "pcie") == 0) {
        leap->transport = LEAP_PCIE;
        if (leap->role != SOCK_CLIENT) {
            printf("\n\nERROR: when using PCIE, argv[1] must be \"client\"\n\n");
            exit(EXIT_FAILURE);
        }

    } else if (strcmp(argv[2], "tcp") == 0) {
        leap->transport = LEAP_TCP;
    } else if (strcmp(argv[2], "rdma") == 0) {
        leap->transport = LEAP_RDMA;
    } else if(strcmp(argv[2], "stripe") == 0) {
	    leap->transport = LEAP_STRIPE;
	    if(leap->role != SOCK_CLIENT) {
		    printf("\n\nERROR: when using STRIPE, argv[1] must be \"client\"\n\n");
		    exit(EXIT_FAILURE);
	    }
    } else if(strcmp(argv[2], "raid1") == 0) {
	    leap->transport = LEAP_RAID1;
	    if(leap->role != SOCK_CLIENT) {
		    printf("\n\nERROR: when using RAID1, argv[1] must be \"client\"\n\n");
		    exit(EXIT_FAILURE);
	    }
    } else if(strcmp(argv[2], "azure") == 0) {
	    leap->transport = LEAP_AZURE;
	    if(leap->role != SOCK_AZURE) {
		    printf("\n\nERROR: when using AZURE, argv[1] must be \"client\"\n\n");
		    exit(EXIT_FAILURE);
	    }
    } else {
        printf("\nError: argv[2] must be \"pcie\" or \"tcp\" or \"rdma\"\n\n");
        usage();
    }
    printf("Coperd,transport: %s\n", argv[2]);

    /* For LocalSSD, no need to setup IP and port */
    if (leap->transport == LEAP_PCIE && argc == 3) {
        return 0;
    }

#if defined(__x86_64__)
    if(leap->transport == LEAP_AZURE) {
      return 0;
    }
#endif

    if (leap->transport == LEAP_PCIE && argc > 3) {
        printf("\n\nCoperd,routing vQP via RDMA !! \n\n");
    }

    /* For TCPSSD and RDMASSD, we need specifically 5 parameters */
    //assert(argc == 5);
    strcpy((char *)leap->ip, argv[3]);
    leap->port = atoi(argv[4]);
    printf("Coperd,IP:%s,Port:%d\n", leap->ip, leap->port);

#if !defined(__x86_64__)
    if(leap->transport == LEAP_TCP) {
	    strcpy((char *)leap->rdma_ip, argv[5]);
	    leap->rdma_port = atoi(argv[6]);
	    printf("Coperd,RDMA_FE_IP:%s,Port:%d\n", leap->rdma_ip, leap->rdma_port);
    }
#endif

    return 0;
}

#define MAX_NR_HUGE_MR  (16)
static struct huge_1g_memory_region hmr[MAX_NR_HUGE_MR];

int find_dmabuf_desc(struct leap *leap)
{
    int i;
    int idx = 0;
    uint64_t *dmabuf_desc_ptr = (uint64_t *)((uintptr_t)leap->dmabuf + 4096);

    for (i = 0; i < NR_HMR_FIELDS * MAX_NR_HUGE_MR; i += NR_HMR_FIELDS) {
        if (dmabuf_desc_ptr[i] == 0) {
            break;
        }
        hmr[idx].start_hva = dmabuf_desc_ptr[i];
        hmr[idx].start_hpa = dmabuf_desc_ptr[i + 1];
        hmr[idx].size = dmabuf_desc_ptr[i + 2];
        idx++;
    }

    /* print MR info collected */
    for (i = 0; i < idx; i++) {
        printf("Coperd,hmr[%d],start_hva:0x%lx,start_hpa:0x%lx,size:%ld\n", i,
                hmr[i].start_hva, hmr[i].start_hpa, hmr[i].size);
    }

    leap->nhmrs = idx;
    leap->hmr = hmr;

    //assert(leap->nhmrs == 2);
    /* FIXME later */
    leap->dmabuf_hpa = hmr[0].start_hpa;

    return 0;
}

void server_map_dmabuf(struct leap *leap)
{
#if defined(__x86_64__)
    size_t dmabuf_oft = 250ULL << 30; // 250GB
    /* FIXME: need to support more in future */
    size_t dmabuf_sz = 2ULL << 30; // 1GB
    /* Coperd: O_SYNC will make the performance EXTREMELY bad */
    int devmem_fd = open("/dev/mem", O_RDWR);
    assert(devmem_fd >= 0);

    leap->dmabuf = mmap(NULL, dmabuf_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
            devmem_fd, dmabuf_oft);
    if (leap->dmabuf == MAP_FAILED) {
        printf("Coperd, mmap /dev/mem for host hugepage failed\n");
        exit(1);
    }

    if (memcmp(leap->dmabuf, (void *)"QuantumLeap-DRAM", 16) != 0) {
        printf("Coperd,%s,ERROR,Magic string \"QuantumLeap-DRAM\" not detected!\n",
                __func__);
        //exit(EXIT_FAILURE);
    }

    printf("Map SoCVM DMABUF from host hugepage .. SUCCESS!\n");

    find_dmabuf_desc(leap);
    printf("Coperd,nhmrs=%d\n", leap->nhmrs);
#else
    /* For SVK, allocate one hugepage for DMABUF */
    map_hugepage(leap);
#endif
}


int leap_setup_azure_drive(struct leap *leap, int argc, char** argv)
{
#if defined(__x86_64__)
	if(argc != 6) {
		usage();
	}

	leap->m_conn_string.assign(argv[3]);
	leap->m_vhd_name.assign(argv[4]);
	try {
		quantum_leap::qls_azure_drive::create_drive(leap->m_conn_string,
							    leap->m_vhd_name,
							    (size_t)strtoull(argv[5],
									     NULL, 10));

		leap->m_azure_drive = new quantum_leap::qls_azure_drive(leap->m_conn_string,
									leap->m_vhd_name);
	}catch(std::exception e)
		 {
			 return -1;
		 }

	return 0;
#else
	if(argc != 8) {
		usage();
	}

	leap->m_conn_string.assign(argv[5]);
	leap->m_vhd_name.assign(argv[6]);
	try {
		quantum_leap::qls_azure_drive::create_drive(leap->m_conn_string,
							    leap->m_vhd_name,
							    (size_t)strtoull(argv[7],
									     NULL, 10));

		debug("leap_setup_azure_drive: create new Azure drive\n");

		leap->m_azure_drive = new quantum_leap::qls_azure_drive(leap->m_conn_string,
									leap->m_vhd_name);
		debug("leap_setup_azure_drive: create new Azure drive, instantiate\n");
	}catch(std::exception e)
		 {
			 return -1;
		 }

	return 0;
#endif
}


/* TODO: recheck error handling path */
int main(int argc, char **argv)
{
    int ret;
    struct leap *leap;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        usage();
    }

    leap = (struct leap *)calloc(1, sizeof(struct leap));
    if (!leap) {
        printf("Coperd,%s,malloc leap failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    leap_parse_args(leap, argc, argv);

    ret = leap_init_leap(leap);
    if (ret) {
        goto err_init_leap;
    }

    // set up the Azure storage drive
    if(leap->role == SOCK_AZURE) {
	    ret = leap_setup_azure_drive(leap, argc, argv);

	    if(ret) {
		    printf("Coperd,%s,setup_azure_Drive failed\n", __func__);
		    goto err_setup_endpoint;
	    }

	    debug("main: created Azure drive\n");
    }

#if 1
    ret = map_res(leap);
    if (ret) {
        goto err_map_res;
    }
#endif

    if (leap->transport == LEAP_TCP) {
        printf("Coperd,setting up SOCP TCP connection...\n");
        ret = leap_setup_tcp_endpoint(leap, argc, argv);
        if (ret) {
            printf("Coperd,%s,setup_tcp_endpoint failed\n", __func__);
            goto err_setup_endpoint;
        }
    }

    if ((leap->role == SOCK_CLIENT) || (leap->role == SOCK_AZURE)) {
	    if ((leap->transport == LEAP_PCIE) || (leap->transport == LEAP_AZURE) ||
		(leap->transport == LEAP_TCP)) {
		    /* Coperd: Let's do RDMA setup for vQP routing here */
		    if (leap->use_rdma_for_vqp) {
			    leap_setup_rdma_endpoint_pcie(leap);

			    /*
			     * Coperd: if this runs on SVK, then we need to map DMABUF
			     * initialize dmabuf for server use
			     */
			    server_map_dmabuf(leap);
			    //leap->dmabuf = get_dmabuf_addr_base(leap);
#if !defined(__x86_64__)
			    assert(leap->dmabuf);
			    leap_server_dmabuf_init(leap);
#endif
			    /*
			     * For LocalSSD, client manages both vQP and pQP
			     */
			    //#ifndef CORE_IOPS_TEST		
			    leap_init_pqps(leap);
			    //#endif
		    } else {
			    leap_init_pqps(leap);
		    }
	    } else if (leap->transport == LEAP_RDMA) {
		    /*
		     * For RDMASSD: we need malloc data buffer as RDMA doesn't allow
		     * ibv_reg_mr over BAR memory (where we map host physical memory)
		     */
		    leap_client_rdmabuf_init(leap);
	    }

	    if ((leap->transport == LEAP_STRIPE) || (leap->transport == LEAP_RAID1)) {
		    printf("setting up rdmabufs\n");
		    leap_client_rdmabuf_init(leap);
		    printf("setting up pqps\n");
		    leap_init_pqps_stripe(leap);
	    }

	    printf("setting up vqps\n");

	    /* Coperd: init vQP structure members */
	    leap_init_vqps(leap);
	    printf("Coperd,init_vqps done\n");
    } else if (leap->role == SOCK_SERVER) {
        /* initialize dmabuf for server use */
        server_map_dmabuf(leap);
        //leap->dmabuf = get_dmabuf_addr_base(leap);
        assert(leap->dmabuf);

        leap_server_dmabuf_init(leap);

        if (leap->transport == LEAP_RDMA) {
            /* Similarly, reserved physical memory for DMA doesn't work with RDMA */
            leap_server_rdmabuf_init(leap);
        }

        /* Coperd: pQPs */
        leap_init_pqps(leap);
    }

    if ((leap->transport == LEAP_RDMA) || (leap->transport == LEAP_STRIPE) ||
            (leap->transport == LEAP_RAID1)) {
        printf("Coperd,setting up SOCP RDMA connections...\n");
        /* TODO: handle errors elegantly later */
        leap_setup_rdma_endpoint(leap);
    }

    printf("\n\n Waiting for SOCP to become ready ...\n\n");

    sleep(1);

    printf("=============socp ready for processing commands===============\n");

#if 0
    printf("Coperd, Done...\n");
    exit(1);
#endif

#ifdef USE_LEAP_THREADS
    /* NOT USED NOW */
    /* Kick start workers: submitter and completer for req processing */
    /* submitter in one thread and completer in another */
    ret = leap_init_submitter(leap);
    if (ret) {
        goto err_init_submitter;
    }

    ret = leap_init_completer(leap);
    if (ret) {
        goto err_init_completer;
    }
#else
    /*
     * Coperd: WE ARE ACTUALLY USING THIS PATH FOR SOCP
     */
    ret = leap_init_poller(leap);
    if (ret) {
        goto err_init_poller;
    }
#endif

    leap_wait_for_end(leap);

    /* Coperd: free allocted memory here */
    leap_free_leap(leap);

    /* Coperd: put this at the end */
    cleanup();

    return 0;

#ifdef USE_LEAP_THREADS
err_init_completer:
    free(leap->submitter);
err_init_submitter:
#else
err_init_poller:
#endif
err_setup_endpoint:
err_map_res:
    free(leap->vqps);
    free(leap->pqps);
err_init_leap:
    free(leap);

    return ret;
}
