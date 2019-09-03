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

#ifndef MY_Z80_SPECK_H
#define MY_Z80_SPECK_H

#define MY_SPECK_ROUNDS (27)

struct ciph_iface * make_my_z80_speck(void);

struct my_z80_speck
{
	uint32_t k[MY_SPECK_ROUNDS];
	
	struct z80_context * z80;
};


enum z80_speck_procs
{
	Z80_SP_INIT = 0x0030,
	Z80_SP_SETKEY = 0x0000,
	Z80_SP_ENCRYPT = 0x0010,
	Z80_SP_DECRYPT = 0x0020
};

enum z80_speck_keys
{
	Z80_SP_KEYS_ADDR = 0x4100
};

enum z80_speck_data
{
	Z80_SP_INKEY_ADDR = 0x4000,
	Z80_SP_INDATA_ADDR = 0x6000,
	Z80_SP_OUTDATA_ADDR = 0x6100
};

enum z80_speck_state
{
	Z80_SP_STATE_ADDR = 0x5000
};






int  my_z80_speck_ciph_init  (struct ciph_iface * ciph);
int  my_z80_speck_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size);
int  my_z80_speck_ciph_enc   (struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size);
int  my_z80_speck_ciph_dec   (struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size);
void my_z80_speck_ciph_deinit(struct ciph_iface * ciph);




#endif // MY_Z80_SPECK_H

