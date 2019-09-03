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

#ifndef MY_Z80_AES128_H
#define MY_Z80_AES128_H

#define MY_AES128_ROUNDS (10)

struct ciph_iface * make_my_z80_aes128(void);

struct my_z80_aes128
{
	uint8_t kw[16*(MY_AES128_ROUNDS+1)]; // expanded key for encrypting
	uint8_t dw[16*(MY_AES128_ROUNDS+1)]; // --//-- for decrypting

	uint8_t sbox[256];
	uint8_t ibox[256];

	uint8_t box02[256];
	uint8_t box03[256];
	//
	uint8_t box09[256];
	uint8_t box0B[256];
	uint8_t box0D[256];
	uint8_t box0E[256];

	struct z80_context * z80;
};

enum z80_proc_addresses
{
	Z80_AES_INIT    = 0x0000,
	Z80_AES_SETKEY  = 0x0010,
	Z80_AES_ENCRYPT = 0x0020
};

enum z80_data_addresses
{
	Z80_SBOX_ADDR = 0x4000,
	Z80_BOX02_ADDR = 0x4100,
	Z80_BOX03_ADDR = 0x4200,

	Z80_KEYS_ADDR = 0x5000,
	Z80_STATE_ADDR = 0x50C0,

	Z80_INKEY_ADDR = 0x6000,
	Z80_INDATA_ADDR = 0x6100,
	Z80_OUTDATA_ADDR = 0x6200
};



int  my_z80_aes128_ciph_init  (struct ciph_iface * ciph);
int  my_z80_aes128_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size);
int  my_z80_aes128_ciph_enc   (struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size);
int  my_z80_aes128_ciph_dec   (struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size);
void my_z80_aes128_ciph_deinit(struct ciph_iface * ciph);




#endif // MY_Z80_AES128_H

