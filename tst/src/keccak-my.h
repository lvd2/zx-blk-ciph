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

#ifndef KECCAK_MY_H
#define KECCAK_MY_H



#define MY_KECCAK_RATE (136)

struct my_keccak
{
	unsigned int pos;

	uint64_t state[25];
};



struct hash_iface * make_keccak_my(void);

int    keccak_my_hash_init    (struct hash_iface * hash);
int    keccak_my_hash_start   (struct hash_iface * hash);
int    keccak_my_hash_addbytes(struct hash_iface * hash, uint8_t * message, size_t size);
size_t keccak_my_hash_getsize (struct hash_iface * hash);
int    keccak_my_hash_result  (struct hash_iface * hash, uint8_t * result);
void   keccak_my_hash_deinit  (struct hash_iface * hash);




#endif // KECCAK_MY_H

