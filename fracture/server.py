#!/usr/bin/env python3

import ast
import types
import opcode

WHITELIST = [
    'EXTENDED_ARG', 'LOAD_CONST', 'RESUME', 'RETURN_VALUE',
]    

def validate_instructions(instructions):
    assert isinstance(instructions, list)

    for element in instructions:
        assert isinstance(element, tuple)
        assert len(element) == 2

        opname, oparg = element 

        assert isinstance(opname, str)
        assert isinstance(oparg, int)

def build_bytecode(instructions):
    result = bytearray()

    for opname, oparg in instructions:
        if opname in WHITELIST:
            result.append(opcode.opmap[opname])
            result.append(oparg)

    return bytes(result)

def main():
    print('[*] Hello. Please, exploit this.')
    print(f'[+] hex(id(None)) = {hex(id(None))}')

    instructions = ast.literal_eval(input('> '))

    validate_instructions(instructions)
    bytecode = build_bytecode(instructions)

    code = types.CodeType(
        0,          # argcount
        0,          # posonlyargcount
        0,          # kwonlyargcount
        0,          # nlocals
        0,          # stacksize
        0,          # flags
        bytecode,   # codestring
        (),         # constants
        (),         # names
        (),         # varnames
        '',         # filename
        'exploit',  # name
        'exploit',  # qualname
        0,          # firstlineno
        b'',        # linetable
        b'',        # exceptiontable
    )

    result = eval(code)
    print(result)

if __name__ == '__main__':
    main()
