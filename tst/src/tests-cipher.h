// Z80 ciphers test framework
// (c) 2019 lvd^mhm

/*
    This file is part of Z80 ciphers test framework.

    Z80 ciphers test framework is free software:
    you can redistribute it and/or modify it under the terms of
    the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Z80 ciphers test framework is distributed in the hope that
    it will be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Z80 ciphers test framework.
    If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef TESTS_CIPHER_H
#define TESTS_CIPHER_H

struct tests_cipher
{
	const char * hex_key;
	const char * hex_plain;
	const char * hex_cipher;
	unsigned int iterations;
};


extern const struct tests_cipher bf_tests[];
extern const struct tests_cipher aes128_tests[];
extern const struct tests_cipher speck_tests[];


#endif // TESTS_CIPHER_H

