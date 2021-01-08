#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <time.h>

typedef struct NvmeCmd {
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
} NvmeCmd;

void print_nvmecmd(NvmeCmd *cmd)
{
    //printf("-------------------\n");
    printf("opcode:%d,fuse:%d,cid:%d,nsid:%d,prp1:%" PRIu64 ",prp2:%" PRIu64 "\n",
            cmd->opcode, cmd->fuse, cmd->cid, cmd->nsid, cmd->prp1, cmd->prp2);
    //printf("~~~~~~~~~~~~~~~~~~~\n");
}

#define MB (1024 * 1024)
#define GB (1024 * 1024 * 1024)

uint64_t get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return (ts.tv_sec * 1e9 + ts.tv_nsec);
}

int main()
{
    int i;
    uint64_t st_ns, et_ns, tt_ns = 0;
    int niter = 0;

    void *membuf;
    posix_memalign(&membuf, 4096, 1024 * MB);
    assert(membuf);
    memset(membuf, 'b', 256 * MB);
    memset(membuf, 'a', 128 * MB);

#if 0
    int ivsfd = open("/sys/devices/pci0000:00/0000:00:06.0/resource2", O_RDWR | O_SYNC);
    assert(ivsfd >= 0);
    void *ivsbuf = mmap(0, 256*MB, PROT_READ | PROT_WRITE, MAP_SHARED, ivsfd, 0);
    assert(ivsbuf);

    for (i = 0; i <= 40000; i++) {
        st_ns = get_ns();
        //memcpy(membuf, ivsbuf, 4096);
        memcpy(ivsbuf, membuf, 4096);
        et_ns = get_ns();
        membuf += 4096;
        ivsbuf += 4096;
        tt_ns += (et_ns - st_ns);
        niter++;
    }

    printf("Loop: %d, Avg lat: %.2f ns\n", niter, (tt_ns * 1.0) / niter);
#endif

    int hmemfd = open("/dev/mem", O_RDWR/* | O_SYNC*/);
    assert(hmemfd >= 0);
    printf("Coperd, hmemfd=%d\n", hmemfd);
    void *hmembuf = mmap(0, 512ULL << 30, PROT_READ | PROT_WRITE, MAP_SHARED, hmemfd, 0);
    if (hmembuf == MAP_FAILED) {
        printf("Coperd, mmap /dev/mem failed, errno:%d\n", errno);
        exit(1);
    }
    hmembuf += ((256ULL+32ULL) << 30);
    //hmembuf += (250ULL << 30);
    printf("\n\n***** Coperd,%s,******\n\n", (char *)hmembuf);
    exit(1);


    //hmembuf += ((12ULL + 32ULL) << 30);

    //hmembuf += (32ULL << 30);
    //pmembuf += 1ULL * GB + 0x800000000;

    //printf("Coperd,%s,\n", (char *)pmembuf);

    tt_ns = 0;
    niter = 0;
    for (i = 0; i < 1000; i++) {
        //memset(pmembuf, i % 10, 4096);
        st_ns = get_ns();
        //memcpy(pmembuf, membuf, 4096);
        memcpy(membuf, hmembuf, 4096);
        et_ns = get_ns();
        membuf += 4096;
        hmembuf += 4096;
        tt_ns += (et_ns - st_ns);
        niter++;
    }
    printf("Loop: %d, Avg lat: %.2f ns\n", niter, (tt_ns * 1.0) / niter);

    exit(1);

    int devmemfd = open("/dev/mem", O_RDWR);
    assert(devmemfd >= 0);

    size_t msz = 1ULL << 38;

    void *hbuf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, devmemfd, 0);
    if (hbuf == MAP_FAILED) {
        printf("Coperd, mmap /dev/kvm failed\n");
        exit(1);
    }
    hbuf += (24ULL << 30);

    tt_ns = 0;
    niter = 0;
    for (i = 0; i < 1; i++) {
        //memset(pmembuf, i % 10, 4096);
        st_ns = get_ns();
        //memcpy(pmembuf, membuf, 4096);
        memcpy(membuf, hbuf, 4096);
        et_ns = get_ns();
        membuf += 4096;
        hbuf += 4096;
        tt_ns += (et_ns - st_ns);
        niter++;
    }
    printf("Loop: %d, Avg lat: %.2f ns\n", niter, (tt_ns * 1.0) / niter);


    exit(1);


    int fd = open("/sys/devices/pci0000:00/0000:00:05.0/resource2", O_RDWR | O_SYNC);

    void *ptr = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    printf("PCI BAR0 0x0000 = 0x%4x\n",  *((unsigned short *) ptr));

    NvmeCmd *sq = (NvmeCmd *)ptr;

    for (i = 0; i < 10; i++)
        print_nvmecmd(&sq[i]);

    return 0;
}
