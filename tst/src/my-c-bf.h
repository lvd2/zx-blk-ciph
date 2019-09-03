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

#ifndef MY_C_BF_H
#define MY_C_BF_H

#define MY_BF_ROUNDS (16)

struct ciph_iface * make_my_c_bf(void);

struct my_c_bf
{
	uint32_t p[MY_BF_ROUNDS+2];
	uint32_t s0[256];
	uint32_t s1[256];
	uint32_t s2[256];
	uint32_t s3[256];
};


int  my_c_bf_ciph_init  (struct ciph_iface * ciph);
int  my_c_bf_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size);
int  my_c_bf_ciph_enc   (struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size);
int  my_c_bf_ciph_dec   (struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size);
void my_c_bf_ciph_deinit(struct ciph_iface * ciph);




#endif // MY_C_BF_H

