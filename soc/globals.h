/* Global Variables for LeapIO Project */

/*
 * ***********************************************************
 * Gobal parameters need to be manually set correctly for now
 * ***********************************************************
 */

#define NR_HOST_CPUS        (8)
#define VQP_DEPTH           (1024)
#define MAX_NR_VQPS         (16)
#define NR_DBVMS            (4)  /* IMPORTANT */

/*
 * 1 for enabling routing vQP via RDMA, 0 for using default shared memory for vQP
 * sharing
 */
#define RDMA_VQP_SHARING    (1)

/* TOFIX TOFIX TOFIX */
#define DATA_SHIFT          (12) /* 4K sector size */
#define mdts                (5)  /* [2<<5 * (4KB) = 128KB] == MDTS */
#define MAX_PRPS            (2 << mdts)
#define MDTS                (MAX_PRPS * 4096) /* 128 KB */

/* only for the server side (SoC-VM or SVK): add "memmap=4G$8G" to kernel parameters */
#define PHY_RSV_DMABUF_BASE (8ULL*1024*1024*1024) /* 8GB-8GB+4GB for DMA */
#define PHY_RSV_DMABUF_SZ   (4ULL*1024*1024*1024) /* 4GB */
#define PHY_RSV_DMABUF_END  (PHY_RSV_DMABUF_BASE + PHY_RSV_DMABUF_SZ)

/* End of global parameters */

