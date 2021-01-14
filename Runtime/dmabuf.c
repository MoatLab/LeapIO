/*
 * File dmabuf.c
 * Simple DMA buffer allocator for LeapIO
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

#include "inc/stdinc.h"
#include "inc/leap.h"
#include "globals.h"

/*
 * DMA buffer memory management for QuantumLeap Project
 *
 * For SoC-VM, we reserve continuous physical memory region on host machine
 *
 * For SoC, can we do the same by reserving physical memory for DMA? Otherwise
 * we pre-allocate enough memory buffers using hugepages, do VA->PA translation
 * first and then use them as DMA buffers, the latter will take time when doing
 * iov->prp translation where VA->PA translation is needed, the worst case is to
 * use pre-allocated not-guaranteed-continous 4K memory buffers
 *
 * A simple memory allocator is implemented based on the buffers above
 *
 * Currently, DMA buffers should be associated with each physical queue pair
 *
 * Notice: this is only needed by Leap-Server
 *
 * TODO: Need a well-implemented memory allocator
 */

/* Pre-alloc SoC memory for RDMA (send/recv, and rcmdbuf/rcplbuf) */
void leap_rdmabuf_init(struct leap *leap)
{
#if defined(__x86_64__)
    int i, j;
    void *rdmabuf;
    uintptr_t cur_addr;
    int max_prps = MAX_PRPS + 8; /* TODO TODO: original +8 for safety */
    int nr_rdma_descs;

    assert(leap->pgsz == 4096);

    /* we need two buffers: one for RDMA Send and the other for RDMA Recv */
    nr_rdma_descs = VQP_DEPTH * NR_DBVMS * 2 * 2; /* time two for striping */
    leap->rdmabuflen = (uint64_t)leap->pgsz * max_prps * nr_rdma_descs;

    printf("Coperd,allocating rdmabuf:%.2f MB\n", 1.0 * leap->rdmabuflen / MB);
    leap->rdmabuf = calloc(1, leap->rdmabuflen);
    if (!leap->rdmabuf) {
        printf("Coperd,%s,failed to allocate rdmabuf\n", __func__);
        exit(EXIT_FAILURE);
    }

    rdmabuf = leap->rdmabuf;
    cur_addr = (uintptr_t)rdmabuf;

    leap->rdma_descs = (dma_desc *)calloc(nr_rdma_descs, sizeof(dma_desc));
    assert(leap->rdma_descs);
    QTAILQ_INIT(&leap->rdma_desc_list);

    for (i = 0; i < nr_rdma_descs; i++) {
        leap->rdma_descs[i].max_prps = max_prps;
        leap->rdma_descs[i].iov = (struct iovec *)malloc(sizeof(struct iovec) * max_prps);
        memset(leap->rdma_descs[i].iov, 0, sizeof(struct iovec) * max_prps);
        for (j = 0; j < max_prps; j++) {
            leap->rdma_descs[i].iov[j].iov_base = (void *)cur_addr;
            leap->rdma_descs[i].iov[j].iov_len = leap->pgsz; /* default page size */
            /* zero dmabuf pages */
            memset((void *)cur_addr, 0, leap->pgsz);
            cur_addr += leap->pgsz;
        }
        QTAILQ_INSERT_TAIL(&leap->rdma_desc_list, &leap->rdma_descs[i], entry);
    }
#else
    /* on SVK, we can use the same hugepage buf for both local DMA and RDMA */
    /* No need to allocate separate buffer for RDMA as in SoCVM */
    /* TODO: for now, keep it the same as in x86, b/c we need rbuf and sbuf for
     * RDMA ... one thing we can do now is to use hugepage */
    int i, j;
    void *rdmabuf;
    uintptr_t cur_addr;
    int max_prps = MAX_PRPS + 8; /* TODO TODO: original +8 for safety */
    int nr_rdma_descs;

    assert(leap->pgsz == 4096);

    /* we need two buffers: one for RDMA Send and the other for RDMA Recv */
    nr_rdma_descs = VQP_DEPTH * NR_DBVMS * 2;
    leap->rdmabuflen = (uint64_t)leap->pgsz * max_prps * nr_rdma_descs;

    printf("Coperd,allocating rdmabuf:%.2f MB\n", 1.0 * leap->rdmabuflen / MB);
    leap->rdmabuf = calloc(1, leap->rdmabuflen);
    if (!leap->rdmabuf) {
        printf("Coperd,%s,failed to allocate rdmabuf\n", __func__);
        exit(EXIT_FAILURE);
    }

    rdmabuf = leap->rdmabuf;
    cur_addr = (uintptr_t)rdmabuf;

    leap->rdma_descs = (dma_desc *)calloc(nr_rdma_descs, sizeof(dma_desc));
    assert(leap->rdma_descs);
    QTAILQ_INIT(&leap->rdma_desc_list);

    for (i = 0; i < nr_rdma_descs; i++) {
        leap->rdma_descs[i].max_prps = max_prps;
        leap->rdma_descs[i].iov = (struct iovec *)malloc(sizeof(struct iovec) * max_prps);
        memset(leap->rdma_descs[i].iov, 0, sizeof(struct iovec) * max_prps);
        for (j = 0; j < max_prps; j++) {
            leap->rdma_descs[i].iov[j].iov_base = (void *)cur_addr;
            leap->rdma_descs[i].iov[j].iov_len = leap->pgsz; /* default page size */
            /* zero dmabuf pages */
            memset((void *)cur_addr, 0, leap->pgsz);
            cur_addr += leap->pgsz;
        }
        QTAILQ_INSERT_TAIL(&leap->rdma_desc_list, &leap->rdma_descs[i], entry);
    }
#endif
}

void leap_client_rdmabuf_init(struct leap *leap)
{
    leap_rdmabuf_init(leap);
}

void leap_server_rdmabuf_init(struct leap *leap)
{
    leap_rdmabuf_init(leap);
}


#if 1

/* DMA buffer reserved from multiple 1GB hugepages, for SoCVM-server use only */
void leap_server_dmabuf_init(struct leap *leap)
{
    int i, j;
    /* FIXME: dmabuf for hugepage, only using one 1GB hugepage for now */
    void *dmabuf = leap->dmabuf;
    uintptr_t cur_addr = (uintptr_t)dmabuf;
    int max_prps = MAX_PRPS + 1; /* TODO TODO */
    size_t used_bytes = 0;

    assert(leap->pgsz == 4096);
    /* TODO: not safe */
    leap->dma_descs = (dma_desc *)malloc(sizeof(dma_desc) * VQP_DEPTH * NR_DBVMS);
    assert(leap->dma_descs);
    memset(leap->dma_descs, 0, sizeof(dma_desc) * VQP_DEPTH);
    QTAILQ_INIT(&leap->dma_desc_list);

    for (i = 0; i < VQP_DEPTH * NR_DBVMS; i++) {
        leap->dma_descs[i].max_prps = max_prps;
        leap->dma_descs[i].iov = (struct iovec *)malloc(sizeof(struct iovec) * max_prps);
        memset(leap->dma_descs[i].iov, 0, sizeof(struct iovec) * max_prps);
        for (j = 0; j < max_prps; j++) {
            leap->dma_descs[i].iov[j].iov_base = (void *)cur_addr;
            leap->dma_descs[i].iov[j].iov_len = leap->pgsz; /* default page size */
            /* zero dmabuf pages */
            memset((void *)cur_addr, 0, leap->pgsz);
            cur_addr += leap->pgsz;
            used_bytes += leap->pgsz;
            assert(used_bytes <= (2ULL << 30));
        }
        QTAILQ_INSERT_TAIL(&leap->dma_desc_list, &leap->dma_descs[i], entry);
    }
}

void *leap_dmabuf_get(struct leap *leap)
{
    return NULL;
}

void *leap_dmabuf_put(struct leap *leap)
{
    return NULL;
}


#else

////////////////////////////////////////////////////////////////////////////////
//       OLD OLD OLD OLD Logic using host reserved memory via "memmap"
//       Causing IVSHMEM memcpy very slow, 100-200us for memcpy 4K data
////////////////////////////////////////////////////////////////////////////////

/*
 * initialize buffer area according to MDTS
 * SoC-VM: memory come from host, we map it into socp virtual addr space
 * SoC: reserved SoC physical memory region
 *
 * TODO: only consider enough DMA buf for leap->nr_pqps QPs
 */
void leap_server_dmabuf_init(struct leap *leap)
{
    int i, j;
    void *dmabuf = leap->dmabuf;
    uintptr_t cur_addr = (uintptr_t)dmabuf;
    int max_prps = MAX_PRPS + 8; /* TODO TODO */

    assert(leap->pgsz == 4096);
    /* TODO: not safe */
    leap->dma_descs = (dma_desc *)malloc(sizeof(dma_desc) * VQP_DEPTH * NR_DBVMS);
    assert(leap->dma_descs);
    memset(leap->dma_descs, 0, sizeof(dma_desc) * VQP_DEPTH);
    QTAILQ_INIT(&leap->dma_desc_list);

    for (i = 0; i < VQP_DEPTH * NR_DBVMS; i++) {
        leap->dma_descs[i].max_prps = max_prps;
        leap->dma_descs[i].iov = (struct iovec *)malloc(sizeof(struct iovec) * max_prps);
        memset(leap->dma_descs[i].iov, 0, sizeof(struct iovec) * max_prps);
        for (j = 0; j < max_prps; j++) {
            leap->dma_descs[i].iov[j].iov_base = (void *)cur_addr;
            leap->dma_descs[i].iov[j].iov_len = leap->pgsz; /* default page size */
            /* zero dmabuf pages */
            memset((void *)cur_addr, 0, leap->pgsz);
            cur_addr += leap->pgsz;
        }
        QTAILQ_INSERT_TAIL(&leap->dma_desc_list, &leap->dma_descs[i], entry);
    }
}

void *leap_dmabuf_get(struct leap *leap)
{
    return NULL;
}

void *leap_dmabuf_put(struct leap *leap)
{
    return NULL;
}

#endif
