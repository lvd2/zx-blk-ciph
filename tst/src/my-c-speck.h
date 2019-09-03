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

#ifndef MY_C_SPECK_H
#define MY_C_SPECK_H

#define MY_SPECK_ROUNDS (27)

struct ciph_iface * make_my_c_speck(void);

struct my_c_speck
{
	uint32_t k[MY_SPECK_ROUNDS];
};


int  my_c_speck_ciph_init  (struct ciph_iface * ciph);
int  my_c_speck_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size);
int  my_c_speck_ciph_enc   (struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size);
int  my_c_speck_ciph_dec   (struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size);
void my_c_speck_ciph_deinit(struct ciph_iface * ciph);




#endif // MY_C_SPECK_H

