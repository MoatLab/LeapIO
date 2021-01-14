/*
 * File svk.c
 *
 * Storage direct access utitilies from BRCM-SVK SoC user-space, as part of
 * LeapIO runtime
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#include "inc/nvme.h"
#include "inc/leap.h"


struct leap_qpbuf qpbuf[MAX_QPBUF];
struct leap_qpbuf_socp qpbuf_socp[MAX_QPBUF];

#define NVMECDEV            "/dev/nvme0"
#define NVME_IOCTL_LEAP     (0x47)


/* For mapping hugepages on SVK */
#define HPFILE_NAME "/dev/hugepages/hugepagefile"
#define HPLENGTH (1ULL << 30)
#define PROTECTION (PROT_READ | PROT_WRITE)

#define ADDR (void *)(0x0UL)
#define FLAGS (MAP_SHARED)

static void check_bytes(char *addr)
{
	printf("First hex is %x\n", *((unsigned int *)addr));
}

static void write_bytes(char *addr)
{
	unsigned long i;

	for (i = 0; i < HPLENGTH; i++)
		*(addr + i) = (char)i;
}

static int read_bytes(char *addr)
{
	unsigned long i;

	check_bytes(addr);
    for (i = 0; i < HPLENGTH; i++) {
        if (*(addr + i) != (char)i) {
            printf("Mismatch at %lu\n", i);
            return 1;
        }
    }

	return 0;
}

int map_pqps(void)
{
    int ret;
    int nvmefd;
    int devmemfd;
    int qpbuf_socp_idx;
    size_t sqsz = NVME_CMD_SZ * 1024;
    size_t cqsz = NVME_CPL_SZ * 1024;
    void *dbbuf;
    uint64_t db_paddr;
    int leap_nr_pqps;
    int i;

    nvmefd = open(NVMECDEV, O_RDWR);
    if (nvmefd <= 0) {
        printf("Coperd,%s,open %s failed\n", __func__, NVMECDEV);
        exit(EXIT_FAILURE);
    }

    ret = ioctl(nvmefd, NVME_IOCTL_LEAP, qpbuf);
    if (ret) {
        printf("Coperd,leap_ioctl call failed,errno:%d\n", errno);
        exit(EXIT_FAILURE);
    }

    leap_nr_pqps = qpbuf[0].nr_io_queues_leap;

    devmemfd = open("/dev/mem", O_RDWR);
    if (devmemfd <= 0) {
        printf("Coperd,%s,open /dev/mem failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    /* Coperd: map DB page first */
    db_paddr = qpbuf[2].db_paddr - 0x10;
    assert(db_paddr % 4096 == 0);
    printf("Coperd,%s,NVMe Doorbell Addr:0x%lx\n", __func__, db_paddr);
    dbbuf = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, devmemfd, db_paddr);
    if (dbbuf == MAP_FAILED) {
        printf("Coperd,%s,mmap pDB page failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    /* Coperd: leap->pqps starts with idx: 1 */
    qpbuf_socp_idx = 1;
    /* Coperd: QL qpair starts with qid=2 */
    for (i = 2; i < leap_nr_pqps; i++) {
        struct leap_qpbuf_socp *pqp = &qpbuf_socp[qpbuf_socp_idx];

        pqp->qid = qpbuf[i].qid;
        pqp->q_depth = qpbuf[i].q_depth;
        printf("Coperd,%s,qpbuf[%d],sq_paddr=0x%lx,cq_paddr=0x%lx\n", __func__,
                i, qpbuf[i].sq_paddr, qpbuf[i].cq_paddr);
        pqp->sqbuf = mmap(0, sqsz, PROT_READ | PROT_WRITE, MAP_SHARED, devmemfd, qpbuf[i].sq_paddr);
        pqp->cqbuf = mmap(0, cqsz, PROT_READ | PROT_WRITE, MAP_SHARED, devmemfd, qpbuf[i].cq_paddr);
        if (pqp->sqbuf == MAP_FAILED || pqp->cqbuf == MAP_FAILED) {
            printf("Coperd,mmap sqbuf/cqbuf for qid:%d failed\n", pqp->qid);
            exit(EXIT_FAILURE);
        }

        pqp->sqdb = (uint32_t *)((uintptr_t)dbbuf + pqp->qid * 8);
        pqp->cqdb = (uint32_t *)((uintptr_t)pqp->sqdb + 4);

        qpbuf_socp_idx++;
    }

    return 0;
}

int map_hugepage(struct leap *leap)
{
    int hfd;
    int pagemap_fd;

    hfd = open(HPFILE_NAME, O_CREAT | O_RDWR, 0755);
    if (hfd < 0) {
        printf("Coperd,%s,Open [%s] failed", __func__, HPFILE_NAME);
        exit(EXIT_FAILURE);
    }

    leap->dmabuf = mmap(ADDR, HPLENGTH, PROTECTION, FLAGS, hfd, 0);
    if (leap->dmabuf == MAP_FAILED) {
        printf("Coperd,%s,mmap [%s] failed", __func__, HPFILE_NAME);
        unlink(HPFILE_NAME);
        exit(EXIT_FAILURE);
    }

    check_bytes((char *)leap->dmabuf);
    write_bytes((char *)leap->dmabuf);
    read_bytes((char *)leap->dmabuf);

    /* let's get leap->dmabuf_hpa here too */
    pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd <= 0) {
        printf("Coperd,%s,open /proc/self/pagemap failed,errno:%d\n", __func__,
                errno);
        exit(EXIT_FAILURE);
    }

    leap->dmabuf_hpa = pagemap_va2pa(pagemap_fd, leap->dmabuf);
    printf("Coperd,%s,dmabuf paddr:0x%lx\n", __func__, leap->dmabuf_hpa);

    return 0;
}
