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

#define MAX_QPBUF (256)

struct leap_qpbuf qpbuf[MAX_QPBUF];

int map_devmem(void)
{
    return open("/dev/mem", O_RDWR);
}

extern int fd;

void prepare_addr_translation(void)
{
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    printf("Coperd,%s,pagemap fd:%d\n", __func__, fd);
}

extern uint64_t va2pa(void *addr);

int main(int argc, char **argv)
{
    int nvmefd;
    int devmemfd;
    int ret;
    void *sqbuf;
    void *cqbuf;
    void *dbbuf;

#if defined(__x86_64__)
    printf("Hello from X86\n");
#elif defined(__aarch64__)
    printf("Hello from Aarch64\n");
#endif

    nvmefd = open("/dev/nvme0", O_RDWR);
    assert(nvmefd > 0);

    ret = ioctl(nvmefd, 0x47, qpbuf);
    if (ret) {
        printf("Coperd,leap_ioctl call failed,errno:%d\n", errno);
        exit(1);
    }

    devmemfd = map_devmem();
    assert(devmemfd > 0);

    sqbuf = mmap(0, 64*1024, PROT_READ | PROT_WRITE, MAP_SHARED, devmemfd, qpbuf[2].sq_paddr);
    if (sqbuf == MAP_FAILED) {
        printf("Coperd,map /dev/mem failed\n");
        exit(1);
    }

    dbbuf = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, devmemfd, qpbuf[2].db_paddr - 0x10);
    if (dbbuf == MAP_FAILED) {
        printf("Coperd,map dbbuf failed\n");
        exit(1);
    }

    void *data;
    posix_memalign(&data, 4096, 4096);
    assert(data);

    int i;
    for (i = 0; i < 4095; i++) {
        ((char *)data)[i] = 'a' + i % 26;
    }

    prepare_addr_translation();
    assert(fd > 0);

    // send one command
    struct nvme_command c = {0};
    //c.rw.opcode = NVME_CMD_WRITE;
    c.rw.opcode = NVME_CMD_READ;
    memset(data, 0, 4096);
    c.rw.cid = 1;
    c.rw.nsid = 1;
    c.rw.prp1 = va2pa(data);
    c.rw.slba = 0;

    memcpy((void *)(&((struct nvme_command *)sqbuf)[1]), &c, NVME_CMD_SZ);
    uint32_t *db = (dbbuf + 0x10);
    *db = 2;

    printf("Coperd, cmd submitted, data=[%s]\n", (char *)data);

    sleep(1);


    printf("After,data=[%s]\n", (char *)data);

    return 0;
}
