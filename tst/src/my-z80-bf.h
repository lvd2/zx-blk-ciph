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

#ifndef MY_Z80_BF_H
#define MY_Z80_BF_H

#define MY_BF_ROUNDS (16)

struct ciph_iface * make_my_z80_bf(void);

struct my_z80_bf
{
	uint32_t p[MY_BF_ROUNDS+2];
	uint32_t s0[256];
	uint32_t s1[256];
	uint32_t s2[256];
	uint32_t s3[256];
	
	struct z80_context * z80;
};

enum z80_bf_procs
{
	Z80_BF_INIT = 0x0030,
	Z80_BF_SETKEY = 0x0000,
	Z80_BF_ENCRYPT = 0x0010,
	Z80_BF_DECRYPT = 0x0020
};

enum z80_bf_keys
{
	Z80_BF_KEYS_ADDR = 0x5000
};

enum z80_bf_s
{
	Z80_BF_S0_B0_ADDR = 0x4000,
	Z80_BF_S0_B1_ADDR = 0x4100,
	Z80_BF_S0_B2_ADDR = 0x4200,
	Z80_BF_S0_B3_ADDR = 0x4300,
                               
	Z80_BF_S1_B3_ADDR = 0x4400,
	Z80_BF_S1_B2_ADDR = 0x4500,
	Z80_BF_S1_B1_ADDR = 0x4600,
	Z80_BF_S1_B0_ADDR = 0x4700,
                               
	Z80_BF_S2_B0_ADDR = 0x4800,
	Z80_BF_S2_B1_ADDR = 0x4900,
	Z80_BF_S2_B2_ADDR = 0x4A00,
	Z80_BF_S2_B3_ADDR = 0x4B00,
                               
	Z80_BF_S3_B3_ADDR = 0x4C00,
	Z80_BF_S3_B2_ADDR = 0x4D00,
	Z80_BF_S3_B1_ADDR = 0x4E00,
	Z80_BF_S3_B0_ADDR = 0x4F00
};

enum z80_bf_data
{
	Z80_BF_INKEY_ADDR = 0x7000,
	Z80_BF_INDATA_ADDR = 0x7100,
	Z80_BF_OUTDATA_ADDR = 0x7200,
	Z80_BF_INKEY_LEN_ADDR = 0x7300,
};

enum z80_bf_state
{
	Z80_BF_STATE_ADDR = 0x6000
};



int  my_z80_bf_ciph_init  (struct ciph_iface * ciph);
int  my_z80_bf_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size);
int  my_z80_bf_ciph_enc   (struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size);
int  my_z80_bf_ciph_dec   (struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size);
void my_z80_bf_ciph_deinit(struct ciph_iface * ciph);




#endif // MY_Z80_BF_H

