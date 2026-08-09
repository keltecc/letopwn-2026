#!/usr/bin/env python3

import cypari2
pari = cypari2.Pari()

primes = None

print('[*] Hello. Please, exploit this.')

while True:
    print(
        '[?] Select an option:\n'
        '1. add primes\n'
        '2. remove primes\n'
        '3. replace primes\n'
        '4. print prime\n'
        '0. exit'
    )

    choice = input('> ')

    if choice == '1':  # add primes
        count = int(input('[?] count: '))

        if count > 0:
            result = pari.addprimes(
                [int(input(f'[?] primes[{i}]: ')) for i in range(count)]
            )

        primes = [prime for prime in result]
        print('[+] done')
        continue

    if choice == '2':  # remove primes
        count = int(input('[?] count: '))

        if count > 0:
            pari.removeprimes(
                [int(input(f'[?] primes[{i}]: ')) for i in range(count)]
            )

        print('[+] done')
        continue

    if choice == '3':  # replace primes
        count = int(input('[?] count: '))

        if count > 0:
            result = (
                [int(input(f'[?] primes[{i}]: ')) for i in range(count)]
            )

        primes = result
        print('[+] done')
        continue

    if choice == '4':  # print prime
        idx = int(input('[?] index: '))
        print(f'[+] primes[{idx}] = {primes[idx]}')
        continue

    if choice == '0':  # exit
        break

    print('[-] Invalid choice.')

print('[*] Bye.')
