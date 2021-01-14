/*
 * File pagemap.c
 * User-space page table walker
 *
 * Written by Huaicheng Li <huaicheng@cs.uchicago.edu>
 */

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

    offset = (uintptr_t)addr / PAGE_SIZE * PAGEMAP_ENTRY_SZ;
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
    if (pfn == (uint64_t)(-1)) {
        printf("Coperd,ERROR,no physical addr mapped!\n");
        exit(1);
    }

#ifdef DEBUG_PAGEMAP
    printf("Coperd,%s,pfn:0x%lx\n", __func__, pfn);
#endif
    return (pfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}
