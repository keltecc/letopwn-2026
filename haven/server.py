#!/usr/bin/env python3

import ctypes

print('[*] Hello. Please, exploit this.')
name = input('[?] Please, enter your name: ')

target = ctypes.create_string_buffer(name.encode(), 0x100)

offset = int(input('[?] offset: '))
buffer = bytes.fromhex(input('[?] buffer (hex): '))

ctypes.memmove(ctypes.addressof(target) + offset, buffer, len(buffer))

print(f'[+] Done. Updated name: {target.value}')
