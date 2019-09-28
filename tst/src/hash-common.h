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

#ifndef HASH_COMMON_H
#define HASH_COMMON_H

// common iface to call any hashes

struct hash_iface
{
	void * hash_specific_data; // for a hash, its specific data (like state)

	const char * name;

	int    (*hash_init)    (struct hash_iface * hash); // 0 is failure
	int    (*hash_start)   (struct hash_iface * hash); // 0 is failure
	int    (*hash_addbytes)(struct hash_iface * hash, uint8_t * message, size_t size); // 0 is failure
	size_t (*hash_getsize) (struct hash_iface * hash); // returns size of the result in bytes
	int    (*hash_result)  (struct hash_iface * hash, uint8_t * result); // 0 is failure. result is written at the given pointer

	void (*hash_deinit)(struct hash_iface * hash);
};





#endif // HASH_COMMON_H

