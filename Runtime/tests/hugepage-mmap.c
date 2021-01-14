#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>

#define FILE_NAME "/dev/hugepages/hugepagefile"
#define LENGTH (1024ULL*1024*1024)
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

    for (i = 0; i < LENGTH; i++)
        *(addr + i) = (char)i;
}

static int read_bytes(char *addr)
{
	unsigned long i;

	check_bytes(addr);
    for (i = 0; i < LENGTH; i++) {
        if (*(addr + i) != (char)i) {
            printf("Mismatch at %lu\n", i);
            return 1;
        }
    }

	return 0;
}

int main(void)
{
    void *addr;
    int fd, ret;

    fd = open(FILE_NAME, O_CREAT | O_RDWR, 0755);
    if (fd < 0) {
        perror("Open failed");
        exit(1);
    }

    addr = mmap(ADDR, LENGTH, PROTECTION, FLAGS, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        unlink(FILE_NAME);
        exit(1);
    }

    check_bytes(addr);
    write_bytes(addr);
    ret = read_bytes(addr);

    memset(addr, 0, 4096);
    memcpy(addr, "QuantumLeap-hugepage", 20);
    memset(addr + (512ULL << 20), 0, 4096);
    memcpy(addr + (512ULL << 20), "AAAAAAAAAAAAAAAAAAAA", 20);
    printf("Returned address is %p,%p,pid:%d\n", addr, addr + (512ULL << 20), getpid());

    getchar();

    munmap(addr, LENGTH);
    close(fd);
    unlink(FILE_NAME);

    return ret;
}
