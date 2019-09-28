# zx-blk-ciph
Test framework for Z80 ciphers.

Currently there are aes128, blowfish and speck ciphers available.

This is still a 'proof-of-concept' project, so there are no Z80 decryptors, only *en*cryptors.

The framework contains some test vectors (key, plaintext, ciphertext) and
applies them to the corresponding cipher implementations.

The framework uses modified libz80 to count cycles of the simulated Z80
execution. The execution ends as soon as `HALT` is executed and the consumed
number of cycles returned to the caller.

The pasmo assembler is also modified to support for some synonyms, like `exd`
for `ex de,hl` or `exa` for `ex af,af'`. More synonyms for index register
halves are added too.

Use `make GCRYPT=1` to build with gcrypt support (only for AES and Blowfish).

Build instructions:

0. go to directory
 cd tst/src

1. build pasmo assembler:
 cd pasmo;
 ./configure;
 make

2. build libz80 library:
 cd libz80;
 make

3. build libkeccak.so from XKPC project (https://github.com/XKCP/XKCP.git). Use 'make asmX86-64/libkeccak.so' for generic amd64 build. You might try generic32/libkeccak.so for other 32bit platforms as first try. This repo contain already contains libkeccak.so for amd64, feel free to re-build.

4. build tests:
 make

5. run tests:
 ./main

You can also run specific Z80 tests (that are not run by default):
 './main aes'
or
 './main bf'
or
 './main speck'
or
 './main keccak'

'./main longkeccak' will add 1Gbyte hashing test vector to keccak tests. Warning! Using both 'keccak' and 'longkeccak' will pass that 1Gbyte string to Z80 implementation, thus resulting in 5-10 hours of calculations (on a modern peecee hardware).

Test vectors for aes and blowfish are taken from various public sources.
First test vector for speck taken from public source, others are generated by
me.

Test vectors for keccak hash generated by KeccakTests from XKCP project (https://github.com/XKCP/XKCP.git).
