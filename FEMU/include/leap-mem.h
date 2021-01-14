#ifndef __LEAP_MEM_H_
#define __LEAP_MEM_H_

#define LEAP_MEMORY_MAX_NREGIONS    (8)

#define LEAP_VERSION_MASK           (0x3)
#define LEAP_REPLY_MASK             (0x1<<2)
#define LEAP_NEED_REPLY_MASK        (0x1 << 3)

typedef enum LeapRequest {
    LEAP_SET_MEM_TABLE = 5,
} LeapRequest;

typedef struct LeapMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t mmap_offset;
} LeapMemoryRegion;

typedef struct LeapMemory {
    uint32_t nregions;
    uint32_t padding;
    LeapMemoryRegion regions[LEAP_MEMORY_MAX_NREGIONS];
} LeapMemory;

typedef struct LeapMsg {
    LeapRequest request;
    uint32_t flags;
    uint32_t size; /* the following payload size */
    union {
        uint64_t u64;
        LeapMemory memory;
    } payload;
} QEMU_PACKED LeapMsg;

static LeapMsg m __attribute__ ((unused));
#define LEAP_HDR_SIZE (sizeof(m.request) \
                            + sizeof(m.flags) \
                            + sizeof(m.size))


#endif
