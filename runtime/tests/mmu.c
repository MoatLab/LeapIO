#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>

//#define DEBUG_PAGEMAP

#define FILE_NAME_SZ_MAX    128

/* pagemap entry size in bytes */
#define PAGEMAP_ENTRY_SZ    8

#define PAGE_SHIFT          12
#define PAGE_SIZE           (1 << PAGE_SHIFT)
#define PFN_PRESENT         (1ull << 63)
#define PFN_PFN             ((1ull << 55) - 1)


uint64_t get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return (ts.tv_nsec + ts.tv_sec * 1e9);
}

uint32_t page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

/* virtual addr to frame number, i.e. GVA -> GFN, or HVA -> HFN */
uint64_t pagemap_va2pfn(int pagemapfd, void *addr)
{
    uint64_t pme, pfn;
    size_t offset;
    int nbytes;

    //offset = ((uintptr_t)addr >> 9) & ~7;
    offset = (uintptr_t)addr / PAGE_SIZE * PAGEMAP_ENTRY_SZ;
    //lseek(pagemapfd, offset, SEEK_SET);
    nbytes = pread(pagemapfd, &pme, 8, offset);
    if (nbytes != 8) {
        printf("Coperd,%s,failed to read 8B for addr translation\n", __func__);
        return -1;
    }

    if (!(pme & PFN_PRESENT))
        return -1;

    pfn = pme & PFN_PFN;

#ifdef DEBUG_PAGEMAP
    printf("Coperd,pfn:%lx\n", pfn);
#endif
    return pfn;
}

/* virtual addr to physical addr, i.e., GVA -> GPA, or HVA -> HPA */
uint64_t pagemap_va2pa(int pagemapfd, void *addr)
{
    uint64_t pfn = pagemap_va2pfn(pagemapfd, addr);
    if (pfn == -1) {
        printf("Coperd,ERROR,no physical addr mapped!\n");
        exit(1);
    }

#ifdef DEBUG_PAGEMAP
    printf("Coperd,%s,pfn:0x%lx\n", __func__, pfn);
#endif
    return (pfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

void usage()
{
    printf("\n\tUsage: ./mmu PID addr\n\n");
    exit(1);
}

#if 1
int main(int argc, char **argv)
{
    uint8_t *ptr;
    uint64_t ptr_mem;
    uint64_t st, et, tt;
    int pagemapfd;

    if (argc != 3) {
        usage();
    }

    long pid = strtol(argv[1], NULL, 10);
    printf("Coperd,pid:%ld\n", pid);

    uint64_t addr = strtoll(argv[2], NULL, 16);
    printf("Coperd,addr:0x%" PRIx64 "\n", addr);

    char *pagemap_filename = malloc(FILE_NAME_SZ_MAX);
    memset(pagemap_filename, 0, FILE_NAME_SZ_MAX);
    sprintf(pagemap_filename, "/proc/%ld/pagemap", pid);
    printf("Coperd,pagemap: %s\n", pagemap_filename);

    pagemapfd = open(pagemap_filename, O_RDONLY);
    if (pagemapfd < 0) {
        perror("open");
        exit(1);
    }

    st = get_ns();
    ptr_mem = pagemap_va2pa(pagemapfd, (void *)addr);
    et = get_ns();
    tt = et - st;
    printf("Your physical address is at 0x%"PRIx64", time:%ld ns\n", ptr_mem, tt);

    getchar();

    return 0;
}
#endif
