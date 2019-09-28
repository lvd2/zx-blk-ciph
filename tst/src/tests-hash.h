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

#ifndef TESTS_HASH_H
#define TESTS_HASH_H

#define HASH_TYPE_HEX (0)
#define HASH_TYPE_STR (1)
#define HASH_TYPE_ARR (2)

struct tests_hash
{
	int type; // HASH_TYPE_HEX or HASH_TYPE_STR

	unsigned int repetitions; // how many times input message should be repeated to the hash function

	size_t msg_len; // length of message for HASH_TYPE_ARR, otherwise ignored
	const char * message; // pointer to the string (for HASH_TYPE_STR) or to hex-string (HASH_TYPE_HEX) or byte array (HASH_TYPE_ARR)

	const char * hex_result;
};


extern const struct tests_hash keccak_256[];      //
extern const struct tests_hash long_keccak_256[]; // r=512, no SHA3 suffix, only 10*1 padding


#endif // TESTS_HASH_H

