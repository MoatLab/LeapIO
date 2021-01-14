#ifndef __LEAP_H
#define __LEAP_H

#include <string>

#include "stdinc.h"
#include "nvme.h"
#include "../rdma-util.h"

#include "qls_azure_drive.h"

#include "snapshot_nvme_pmem.h"

#define KB              (1024)
#define MB              (KB * KB)
#define GB              (1ULL * KB * KB * KB)

struct leap_resource {
    /* Coperd: record all offsets info in the mapped area */
};

typedef struct dma_desc
{
    struct iovec *iov;
    int max_prps;
    QTAILQ_ENTRY(dma_desc) entry;
} dma_desc;

struct huge_1g_memory_region {
    uint64_t start_hva;
    uint64_t start_hpa;
    uint64_t size;
};
/* # of elements in the above structure, be careful */
#define NR_HMR_FIELDS   (3)

enum transport {
    LEAP_PCIE = 0,
    LEAP_TCP = 1,
    LEAP_RDMA = 2,
    LEAP_STRIPE = 3,
    LEAP_RAID1 = 4,
    LEAP_AZURE = 5
};

struct pr_t {
	uint32_t current;
	uint32_t max;
};

struct leap {
    pthread_t *submitter;
    pthread_t *completer;

    int nr_vqps;
    int nr_pqps;
    struct nvme_qpair *vqps;
    struct nvme_qpair *pqps;

    /* Coperd: TODO */
    struct leap_resource res;

    /*
     * Coperd: for each connection, we use two socket connections
     * one (cmd_sockfd) for NVMe command/completion transfer and
     * the other for data buffer transfer
     */
    int role;
    enum transport transport;
    char ip[128];
    int port;

    char rdma_ip[128];
    int rdma_port;
	
    //int cmd_sockfd;
    //int data_sockfd;
    int *sockfds;
    int nfds;

    /* for server only */
    int pgsz;
    void *dmabuf;
    uint64_t dmabuf_hpa;

    struct huge_1g_memory_region *hmr;
    int nhmrs;

    /* for RDMA */

    void *rdmabuf;
    uint64_t rdmabuflen;

    void *cmdbuf;
    uint64_t cmdbuflen;
    void *cplbuf;
    uint64_t cplbuflen;

    /* should be per-dev in future */
    struct dma_desc *rdma_descs;
    struct dma_desc *dma_descs;
    QTAILQ_HEAD(, dma_desc) dma_desc_list;
    QTAILQ_HEAD(, dma_desc) rdma_desc_list;

    /* starting SoC virutal addr of mapped host memory addr space */
    void *host_as_base_va;

    struct rdma_context *rctx;
    struct rdma_event_channel *ec;
    pthread_t cm_event_ts;
    int nr_resolved;
    int nr_connected;

    /* Coperd: for routing vQP via RDMA */
    int use_rdma_for_vqp;
    struct rdma_context *rctx2;
    struct rdma_event_channel *ec2;
    pthread_t cm_event_ts2;
    int nr_resolved2;
    int nr_connected2;
    void *nvme_qpair_buf;
    size_t nvme_qpair_buf_len;

	// counters for priority scheduling
	struct pr_t pr_cnt[2];

        // log needed for snapshots
	snapshot_nvme::snvme_pmem *log;

	std::string m_conn_string;
	std::string m_vhd_name;
	quantum_leap::qls_azure_drive* m_azure_drive;
	
};

enum {
    ERESET = 8000,
    EINACT,
    ESQMAP,
    ENORDY,
};

inline uint64_t min(uint64_t a, uint64_t b)
{
    return ((a < b) ? a : b);
}

inline uint64_t max(uint64_t a, uint64_t b)
{
    return ((a < b) ? b : a);
}

void leap_client_rdmabuf_init(struct leap *leap);
void leap_server_rdmabuf_init(struct leap *leap);
void leap_server_dmabuf_init(struct leap *leap);


void leap_pcqe_to_vcqe(struct nvme_qpair *vqp, struct nvme_completion *cqe);

/* SVK */

extern struct leap_qpbuf_socp qpbuf_socp[MAX_QPBUF];

int map_pqps(void);
int map_hugepage(struct leap *leap);

uint64_t pagemap_va2pa(int pagemapfd, void *addr);

#endif
