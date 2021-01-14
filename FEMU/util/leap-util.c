#include "qemu/osdep.h"
#include "block/block_int.h"
#include "block/qapi.h"
#include "exec/memory.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "hw/pci/msix.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci.h"
#include "qapi/visitor.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/bitops.h"
#include "qemu/bitmap.h"
#include "qom/object.h"
#include "sysemu/sysemu.h"
#include "sysemu/block-backend.h"
#include <qemu/main-loop.h>

#include "leap-util.h"


/* Coperd: 1 -> register vQP info to WPT, 0 -> don't; for debugging only */
static int leap_do_reg = 1;

void *gbuf_hva;

/* Coperd: record the SoC-QEMU vaddr for resource mapping */
void *soc_shared_qpair_buf = NULL;

/* Coperd: global file descriptor of /proc/self/pagemap */
int pagemap_fd = -1;

/* Coperd: global file descriptor of /dev/mem */
int devmem_fd = -1;

/* Coperd: global file descriptor of /dev/wpt */
int wpt_fd = -1;

uint32_t leap_page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t leap_hva2hfn(void *addr)
{
    uint64_t pme, hfn;
    size_t offset;
    int ret;

    offset = ((uintptr_t)addr >> 9) & ~7;
    ret = lseek(pagemap_fd, offset, SEEK_SET);
    if (ret == -1) {
        printf("Coperd,lseek pagemap failed,errno:%d\n", errno);
        return LEAP_INVALID_PFN;
    }

    ret = read(pagemap_fd, &pme, 8);
    if (ret == -1) {
        printf("Coperd,page table walk failed,errno:%d\n", errno);
        return LEAP_INVALID_PFN;
    }

    if (!(pme & PFN_PRESENT))
        return LEAP_INVALID_PFN;

    hfn = pme & PFN_PFN;

    return hfn;
}

uint64_t leap_hva2hpa(void *addr)
{
    uint64_t hfn = leap_hva2hfn(addr);

    assert(hfn != LEAP_INVALID_PFN);

    return (hfn << PAGE_SHIFT) | leap_page_offset((uint64_t)addr);
}

int leap_get_wpt_fd(void)
{
    /* Coperd: return wpt_fd directly if it's already open */
    if (wpt_fd > 0) {
        return wpt_fd;
    }

    printf("Coperd,%s,%d,prepare to open [%s]\n", __func__, __LINE__, LEAP_WPT_DEVNAME);
    wpt_fd = open(LEAP_WPT_DEVNAME, O_RDONLY, S_IRWXU);
    if (wpt_fd == -1) {
        printf("Coperd,cannot open [%s],errno:%d\n", LEAP_WPT_DEVNAME, errno);
        exit(EXIT_FAILURE);
    }
    printf("Coperd,%s,%d,opened [%s] with fd=%d\n", __func__, __LINE__, LEAP_WPT_DEVNAME, wpt_fd);

    return wpt_fd;
}

int leap_get_pagemap_fd(void)
{
    /* Coperd: return pagemap_fd directly if it's already open */
    if (pagemap_fd > 0) {
        return pagemap_fd;
    }

    pagemap_fd = open(LEAP_PAGEMAP_SELF, O_RDONLY, S_IRWXU);
    if (pagemap_fd == -1) {
        printf("Coperd,cannot open [%s],errno:%d\n", LEAP_PAGEMAP_SELF, errno);
        exit(EXIT_FAILURE);
    }

    return pagemap_fd;
}

int leap_get_devmem_fd(void)
{
    /* Coperd: return devmem_fd directly if it's already open */
    if (devmem_fd > 0) {
        return devmem_fd;
    }

    devmem_fd = open(LEAP_DEVMEM, O_RDONLY, S_IRWXU);
    if (devmem_fd == -1) {
        printf("Coperd,cannot open [%s],errno:%d\n", LEAP_DEVMEM, errno);
        exit(EXIT_FAILURE);
    }

    return devmem_fd;
}

int leap_put_wpt_fd(void)
{
    if (wpt_fd < 0)
        return 0;

    close(wpt_fd);
    wpt_fd = -1;
    return 0;
}

int leap_put_pagemap_fd(void)
{
    if (pagemap_fd < 0)
        return 0;

    close(pagemap_fd);
    pagemap_fd = -1;
    return 0;
}

int leap_put_devmem_fd(void)
{
    if (devmem_fd < 0)
        return 0;

    close(devmem_fd);
    devmem_fd = -1;
    return 0;
}

int leap_do_wpt_ioctl_reg(struct wpt_qp_data *data)
{
    int wfd = leap_get_wpt_fd();

    /* Coperd: for debugging */
    if (leap_do_reg == 0) {
        return 0;
    }

    if (ioctl(wfd, WPT_CMD_REG, data) == -1) {
        printf("Coperd,%s,WPT ioctl(%s) failed,errno:%d\n", __func__, "REG",
                errno);
        return -1;
    }

    return 0;
}

int leap_do_wpt_ioctl_unreg(struct wpt_qp_data *data)
{
    int wfd = leap_get_wpt_fd();

    /* Coperd: for debugging */
    if (leap_do_reg == 0) {
        return 0;
    }

    if (ioctl(wfd, WPT_CMD_UNREG, data) == -1) {
        printf("Coperd,%s,WPT ioctl(%s) failed,errno:%d\n", __func__, "UNREG",
                errno);
        return -1;
    }

    return 0;
}

int leap_do_wpt_ioctl_admin_passthru_getbbtbl(struct wpt_admin_passthru_data *pdp)
{
    int wfd = leap_get_wpt_fd();

    if (ioctl(wfd, WPT_CMD_ADMIN_PASSTHRU_GETBBTBL, pdp) < 0) {
        printf("Coperd,%s,WPT ioctl(%s) failed,errno:%d\n", __func__, "PASSTHRU",
                errno);
        return -1;
    }

    return 0;
}

int leap_do_wpt_ioctl_admin_passthru_identity(void *idbuf)
{
    int wfd = leap_get_wpt_fd();

    if (ioctl(wfd, WPT_CMD_ADMIN_PASSTHRU_IDENTITY, idbuf) < 0) {
        printf("Coperd,%s,WPT ioctl(%s) failed,errno:%d\n", __func__, "PASSTHRU",
                errno);
        return -1;
    }

    return 0;
}

int leap_do_wpt_ioctl_map(uint64_t vaddr)
{
    int wfd = leap_get_wpt_fd();

    if (ioctl(wfd, WPT_CMD_MAP, vaddr) == -1) {
        printf("Coperd,%s,WPT ioctl(%s) failed,errno:%d\n", __func__, "MAP",
                errno);
        return -1;
    }

    return 0;
}

int leap_do_wpt_ioctl_unmap(unsigned long vaddr)
{
    int wfd = leap_get_wpt_fd();

    if (ioctl(wfd, WPT_CMD_UNMAP, vaddr) == -1) {
        printf("Coperd,%s,WPT ioctl(%s) failed,errno:%d\n", __func__, "UNMAP",
                errno);
        return -1;
    }

    return 0;
}

int leap_do_wpt_ioctl_get_pdb(unsigned long vaddr)
{
    int wfd = leap_get_wpt_fd();

    if (ioctl(wfd, WPT_CMD_GET_PDB, vaddr)  == -1) {
        printf("Coperd,%s,WPT ioctl(%s) failed,errno:%d\n", __func__,
                "GET_PQP_DB", errno);
        return -1;
    }

    return 0 ;
}

/* Coperd: only work for continuous and page aligned GPAs; use with caution */
int leap_do_qp_mapping(uint64_t gpa)
{
    int ret;
    hwaddr len = PAGE_SIZE; /* Coperd: testing one page */
    gbuf_hva = cpu_physical_memory_map(gpa, &len, 0);
    if (!gbuf_hva) {
        printf("Coperd,cpu_physical_memory_map failed\n");
        return -1;
    }

    /* Coperd: do the addr mapping here */
    ret = leap_do_wpt_ioctl_map((uint64_t)gbuf_hva);
    if (ret != 0) {
        printf("Coperd,failed to guest buffer to any vQP addr\n");
        return -1;
    }

#ifdef DEBUG
    /* Coperd: successful mapping should make gbuf_hva point to SQ now */
    int i;
    NvmeCmd *tsq = (NvmeCmd *)gbuf_hva;
    for (i = 0; i < 10; i++)
        print_nvmecmd(&(tsq[i]));
#endif

    //cpu_physical_memory_unmap(gbuf_hva, len, 0, len);

    return 0;
}

int leap_do_qp_unmapping(void *gbuf_hva)
{
    int ret;
    int len = 4096;

    /* Coperd: restore original HVA->HPA mapping, one page for testing */
    ret = leap_do_wpt_ioctl_unmap((uint64_t)gbuf_hva);
    if (ret == -1) {
        printf("Coperd,do_qp_unmapping failed\n");
        return -1;
    }

    cpu_physical_memory_unmap(gbuf_hva, len, 0, len);

    /* Coperd: TODO: how to check if unmap is successful */

    return 0;
}

void *leap_map_pqp_doorbell(uint64_t hpa, int nbytes)
{
    void *doorbell_buf;
    int mfd = leap_get_devmem_fd();

    doorbell_buf = mmap(0, nbytes, PROT_READ, MAP_SHARED, mfd, hpa);
    if (doorbell_buf == MAP_FAILED) {
        printf("Coperd,%s,failed to map physical doorbells\n", __func__);
        exit(EXIT_FAILURE);
    }

    return doorbell_buf;
}

void leap_unmap_pqp_doorbell(void *doorbell_buf)
{
    int pgsz = getpagesize();

    assert(doorbell_buf);
    munmap(doorbell_buf, pgsz);
}

void leap_init_dbram(MemoryRegion *system_memory)
{
    void *dbram_buf;
    MemoryRegion *dbram_mr;
    hwaddr dbram_oft = 24ULL << 30; // 512MB
    int wpt_fd;

    /* Coperd: add physical NVMe Doorbell registers as guest physical memory */
    dbram_mr = g_malloc(sizeof(*dbram_mr));
    if (posix_memalign(&dbram_buf, 4096, 16*1024*1024)) {
        printf("Coperd,%s,posix_memalign failed\n", __func__);
        exit(1);
    }
    memset(dbram_buf, 0, 4096);
    memset(dbram_buf, 'b', 4095);
    wpt_fd = open("/dev/wpt", O_RDONLY, S_IRWXU);
    if (wpt_fd < 0) {
        printf("Coperd,%s, error opening /dev/wpt\n", __func__);
        exit(1);
    }
    int ret = ioctl(wpt_fd, 15, dbram_buf);
    if (ret < 0) {
        printf("Coperd,%s,map pDB failed\n", __func__);
        exit(1);
    }

    uint32_t *dbs = (uint32_t *)dbram_buf;
    printf("Coperd,%s,@@@@@@@@@@@@@@@@@@@@@@@@@dbs[18]=%d\n", __func__, dbs[18]);
    dbs[18] = 2;
    printf("Coperd,%s,@@@@@@@@@@@@@@@@@@@@@@@@@ set dbs[18]=1\n", __func__);
    memory_region_init_ram_ptr(dbram_mr, NULL, "dbram", 16*1024*1024, dbram_buf);
    memory_region_add_subregion_overlap(system_memory, dbram_oft, dbram_mr, 1);
    close(wpt_fd);
}

void leap_init_eram(MemoryRegion *system_memory)
{
    MemoryRegion *eram_mr;
    void *eram_buf;
    hwaddr eram_oft = 24ULL << 30; // 16GB
    if (posix_memalign(&eram_buf, 4096, 4096)) {
        printf("Coperd,%s,posix_memalign failed\n", __func__);
        exit(1);
    }
    memset(eram_buf, 0, 4096);
    strcpy(eram_buf, "QuantumLeap");
    //memset(eram_buf, 'a', 4095);

    eram_mr = g_malloc(sizeof(*eram_mr));
    memory_region_init_ram_ptr(eram_mr, NULL, "eram-test", 4096, eram_buf);
    memory_region_add_subregion(system_memory, eram_oft, eram_mr);
}



/* hmr for QuantumLeap */

#define FILE_NAME_SZ_MAX    128

/* pagemap entry size in bytes */
#define PAGEMAP_ENTRY_SZ    8

#if 0
#define PAGE_SHIFT          12
#define PAGE_SIZE           (1 << PAGE_SHIFT)
#define PFN_PRESENT         (1ull << 63)
#define PFN_PFN             ((1ull << 55) - 1)
#endif

#define FILE_NAME "/dev/hugepages/leapdmabuf"
#define LENGTH (2ULL*1024*1024*1024)
#define PROTECTION (PROT_READ | PROT_WRITE)

/* Only ia64 requires this */
#ifdef __ia64__
#define ADDR (void *)(0x8000000000000000UL)
#define FLAGS (MAP_SHARED | MAP_FIXED)
#else
#define ADDR (void *)(0x0UL)
#define FLAGS (MAP_SHARED)
#endif

static uint32_t page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

/* virtual addr to frame number, i.e. GVA -> GFN, or HVA -> HFN */
static uint64_t va2pfn(int pagemap_fd, void *addr)
{
    uint64_t pme, pfn;
    size_t offset;
    int nbytes;
    //offset = ((uintptr_t)addr >> 9) & ~7;
    offset = (uintptr_t)addr / PAGE_SIZE * PAGEMAP_ENTRY_SZ;
    lseek(pagemap_fd, offset, SEEK_SET);
    nbytes = read(pagemap_fd, &pme, 8);
    assert(nbytes > 0);
    if (!(pme & PFN_PRESENT)) {
#if 0
        printf("Coperd,PFN_PRESENT not set ... pme & PFN_PFN = 0x%llx, offset:%lx,addr:%p\n", pme & PFN_PFN, offset, addr);
        getchar();
#endif
        return -1;
    }
    pfn = pme & PFN_PFN;
    //printf("Coperd,pfn:%lx\n", pfn);
    return pfn;
}

/* virtual addr to physical addr, i.e., GVA -> GPA, or HVA -> HPA */
static uint64_t va2pa(int pagemap_fd, void *addr)
{
    uint64_t pfn = va2pfn(pagemap_fd, addr);
    if (pfn == -1) {
        printf("Coperd,ERROR,no physical addr mapped to VA:%p\n", addr);
        return -1;
    }

    return (pfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

static void check_bytes(char *addr)
{
	printf("First hex is %x\n", *((unsigned int *)addr));
}

static void write_bytes(char *addr)
{
	uint64_t i;

	for (i = 0; i < LENGTH; i++)
		*(addr + i) = (char)i;
}

static int read_bytes(char *addr)
{
	uint64_t i;

	check_bytes(addr);
	for (i = 0; i < LENGTH; i++)
		if (*(addr + i) != (char)i) {
			printf("Mismatch at %lu\n", i);
			return 1;
		}
	return 0;
}

struct huge_1g_memory_region hmr[MAX_NR_HUGE_MR];

struct huge_1g_memory_region *get_hmr(void)
{
    return hmr;
}

static void find_huge_mem_regions(void *hugebuf)
{
    char pagemap_filename[FILE_NAME_SZ_MAX];
    int pagemap_fd;
    int i;
    int cur_mr_idx = 0;
    int npgs = LENGTH / PAGE_SIZE;
    int idx = 1;
    size_t mrsz;

    memset(pagemap_filename, 0, FILE_NAME_SZ_MAX);
    strcpy((char *)pagemap_filename, "/proc/self/pagemap");

    pagemap_fd = open(pagemap_filename, O_RDONLY);
    if (pagemap_fd < 0) {
        printf("Coperd,%s,open pagemap file failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    hmr[cur_mr_idx].start_hva = (uint64_t)hugebuf;
    hmr[cur_mr_idx].start_hpa = va2pa(pagemap_fd, hugebuf);
    mrsz = PAGE_SIZE;

    for (i = 1; i < npgs; i++) {
        uint64_t taddr = (uint64_t)hugebuf + i * PAGE_SIZE;
        uint64_t thpa = va2pa(pagemap_fd, (void *)taddr);
        if (thpa == (-1)) {
            break;
        }

        if (thpa != (hmr[cur_mr_idx].start_hpa + idx * PAGE_SIZE)) {
            hmr[cur_mr_idx].size = mrsz;
            mrsz = 0;
#if 0
            printf("Coperd,MR[%d],VA:0x%lx,PA:0x%lx,len:%ld\n", cur_mr_idx,
                    hmr[cur_mr_idx].start_hva, hmr[cur_mr_idx].start_hpa,
                    hmr[cur_mr_idx].size);
#endif

            cur_mr_idx++;
            idx = 0;
            hmr[cur_mr_idx].start_hva = taddr;
            hmr[cur_mr_idx].start_hpa = thpa;
        }

        idx++;
        mrsz += PAGE_SIZE;
    }

    hmr[cur_mr_idx].size = mrsz;

    for (i = 0; i <= cur_mr_idx; i++) {
        printf("Coperd,MR[%d],VA:0x%lx,PA:0x%lx,len:%ld\n", i, hmr[i].start_hva,
                hmr[i].start_hpa, hmr[i].size);
    }
}


void leap_init_dmabuf(void)
{
    void *addr;
    int fd, ret;

    fd = open(FILE_NAME, O_CREAT | O_RDWR, 0755);
    if (fd < 0) {
        printf("Open failed, %s", __func__);
        exit(1);
    }

    addr = mmap(ADDR, LENGTH, PROTECTION, FLAGS, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        unlink(FILE_NAME);
        exit(1);
    }

    printf("Coperd,%s,Returned address is %p\n", __func__, addr);

#if 1
    check_bytes(addr);
    write_bytes(addr);
    ret = read_bytes(addr);
#endif

    printf("Coperd,start find_huge_mem_regions\n");
    find_huge_mem_regions(addr);

    printf("Coperd,%s,ret=%d,END\n", __func__, ret);
}

void *leap_map_host_addr_space(void)
{
    //IVShmemState *s = IVSHMEM_COMMON(dev);
    int host_mem_fd;
    uint64_t host_mem_sz;
    void *host_mem_ptr;

    host_mem_fd = open("/dev/mem", O_RDWR);
    if (host_mem_fd < 0) {
        printf("Coperd,%s,open host \"/dev/mem\" file failed!\n", __func__);
    }

    /* Coperd, at most 256GB -> host mem, assuming host DRAM <= 256GB */
    host_mem_sz = (1ULL << 38);
    host_mem_ptr = mmap(NULL, host_mem_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
            host_mem_fd, 0);
    if (host_mem_ptr == MAP_FAILED) {
        printf("Failed to mmap host /dev/mem, make sure\n"
                "(1). Add \"nopat\" to grub (2). Disable CONFIG_STRICT_DEVMEM\n");
        close(host_mem_fd);
        exit(EXIT_FAILURE);
    }
    assert((uintptr_t)host_mem_ptr % PAGE_SIZE == 0);

    return host_mem_ptr;
}
