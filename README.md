Challenges were written for [LetoCTF](https://letoctf.org/) 2026. See [talk.pdf](talk.pdf) (in Russian).

## fracture

Source code: [fracture/server.py](fracture/server.py)

We can run arbitrary bytecode containing only these opcodes:

```python
WHITELIST = [
    'EXTENDED_ARG', 'LOAD_CONST', 'RESUME', 'RETURN_VALUE',
]
```

We're given address leak: `id(None)`.

### Solution

Get `libc_base` and `heap` addresses from the leak.

Exploit out-of-bounds read of `LOAD_CONST` opcode. Construct a fake python object inside the `int` input, write `b'sh\x00'` into reference counter, overwrite its function table to `system()`. Use `LOAD_CONST` to load this fake object via bytecode. Then `system("sh")` will be called.

Example solver: [fracture/solver.py](fracture/solver.py)

### Note

We need to obtain `libc_base` and `heap` addresses with zeroed 30 and 31 bits, since `int` object structure could contain only 30-bit numbers.

Probability ~ 1/16, solution ~ 10s, use multithreading to speed up.

## haven

Source code: [haven/server.py](haven/server.py)

We can write arbitrary data relative to the `target` buffer:

```python
target = ctypes.create_string_buffer(name.encode(), 0x100)
ctypes.memmove(ctypes.addressof(target) + offset, buffer, len(buffer))
```

There is no address leak.

### Solution

We can overwrite function pointer: `builtin_print` -> `os_system`. Then we will call `system()` instead of `print()` there:

```python
print(f'[+] Done. Updated name: {target.value}')
```

Send `'$(cat flag.txt>&2)` as name to inject shell command in the resulting string.

Example solver: [haven/solver.py](haven/solver.py)

### Note

Since we have no leak, we need to bruteforce 3 hex digits of the address.

Probability ~ 1/4096, solution ~ 30s, use multithreading to speed up.

## summit

Source code: [summit/server.py](summit/server.py)

We need to exploit this bug: [cypari2/pull/199](https://github.com/sagemath/cypari2/pull/199). Pari functions `addprimes()` / `removeprimes()` stores dangling pointers to freed objects (UAF).

The challenge provides a well-known heap interface:

```python
print(
    '[?] Select an option:\n'
    '1. add primes\n'
    '2. remove primes\n'
    '3. replace primes\n'
    '4. print prime\n'
    '0. exit'
)
```

There is no address leak.

### Solution

Add and remove some primes to achieve address leak. We can leak `libc_base` and `heap_base` (via reading freed glibc pointers).

Then use `input()` to spray the heap. Do some heap feng shui and overlap chunks to create huge freed chunk. Construct fake python object and put its pointer to `primes` array via spray and heap exploitation. Achieve RIP control via `tp_dealloc` of the fake object. Then find useful gadgets to call `system("/bin/sh")`.

Example solver: [summit/solver.py](summit/solver.py)

### Note

We need three constraints there:

1. `libc_base` 30 and 31 bits should be zeroed
2. `heap_base` 30 and 31 bits should be zeroed
3. `heap_base` should be ASCII printable (bytes < 0x80)

Probability ~ 1/256, solution ~ 5m, use multithreading to speed up.
