#ifndef __WPT_H
#define __WPT_H

#include <sys/ioctl.h>

#define LEAP_WPT_DEVNAME    "/dev/wpt"
#define LEAP_PAGEMAP_SELF   "/proc/self/pagemap"
#define LEAP_DEVMEM         "/dev/mem"

/* Coperd: simply walk page table */
#define WPT_CMD_DUMP        10

/* Coperd: register/unreg SQ/CQ buffer */
#define WPT_CMD_REG         11
#define WPT_CMD_UNREG       17

/* Coperd: map SQ/CQ buffer to user space */
#define WPT_CMD_MAP         12
/* Coperd: swap two user pages for testing */
#define WPT_CMD_UNMAP       13

#define WPT_CMD_SWAP        14
#define WPT_CMD_GET_PDB     18
#define WPT_CMD_ADMIN_PASSTHRU_GETBBTBL 19
#define WPT_CMD_ADMIN_PASSTHRU_IDENTITY 20

/* Coperd: represent queue type */
#define WPT_SQ_T            0
#define WPT_CQ_T            1

#define PAGE_SHIFT          12
#define PAGE_SIZE           (1 << PAGE_SHIFT)
#define PFN_PRESENT         (1ULL << 63)
#define PFN_PFN             ((1ULL << 55) - 1)
#define LEAP_INVALID_PFN    (~0ULL)

/* Coperd: put wpt specific content here */
extern void *gbuf_hva;
extern void *soc_shared_qpair_buf;
extern int pagemap_fd;
extern int devmem_fd;

struct wpt_qp_data;
struct wpt_admin_passthru_data;

uint32_t leap_page_offset(uint32_t addr);
uint64_t leap_hva2hfn(void *addr);
uint64_t leap_hva2hpa(void *addr);
int leap_get_wpt_fd(void);
int leap_get_pagemap_fd(void);
int leap_get_devmem_fd(void);
int leap_put_wpt_fd(void);
int leap_put_pagemap_fd(void);
int leap_put_devmem_fd(void);
int leap_do_wpt_ioctl_reg(struct wpt_qp_data *data);
int leap_do_wpt_ioctl_unreg(struct wpt_qp_data *data);
int leap_do_wpt_ioctl_map(uint64_t vaddr);
int leap_do_wpt_ioctl_unmap(unsigned long vaddr);
int leap_do_qp_mapping(uint64_t gpa);
int leap_do_qp_unmapping(void *gbuf_hva);
int leap_do_wpt_ioctl_get_pdb(unsigned long vaddr);
int leap_do_wpt_ioctl_admin_passthru_getbbtbl(struct wpt_admin_passthru_data *pdp);
int leap_do_wpt_ioctl_admin_passthru_identity(void *buf);
void *leap_map_pqp_doorbell(uint64_t hpa, int nbytes);
void leap_unmap_pqp_doorbell(void *doorbell_buf);

void leap_init_dbram(MemoryRegion *system_memory);
void leap_init_eram(MemoryRegion *system_memory);


struct huge_1g_memory_region {
    uint64_t start_hva;
    uint64_t start_hpa;
    uint64_t size;
};

/* used as dma buffer by SoCVM-server */
#define MAX_NR_HUGE_MR  (16)

void leap_init_dmabuf(void);
struct huge_1g_memory_region *get_hmr(void);
void *leap_map_host_addr_space(void);

#endif
