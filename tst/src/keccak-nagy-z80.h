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

#ifndef KECCAK_NAGY_Z80_H
#define KECCAK_NAGY_Z80_H



#define MY_KECCAK_RATE (136)

struct nagy_z80_keccak
{
	unsigned int pos;

	uint64_t state[25];

	struct z80_context * z80;
};





enum nagy_z80_keccak_procs
{
	Z80_KC_INIT    = 0x0000,
	Z80_KC_ADDBYTE = 0x0010,
	Z80_KC_FINAL   = 0x0020
};

enum nagy_z80_keccak_data
{
	Z80_KC_STATE_ADDR = 0x4100,
	Z80_KC_B_ADDR     = 0x4000,
	Z80_KC_BYTE_ADDR  = 0x5000
};








struct hash_iface * make_keccak_nagy_z80(void);

int    keccak_nagy_z80_hash_init    (struct hash_iface * hash);
int    keccak_nagy_z80_hash_start   (struct hash_iface * hash);
int    keccak_nagy_z80_hash_addbytes(struct hash_iface * hash, uint8_t * message, size_t size);
size_t keccak_nagy_z80_hash_getsize (struct hash_iface * hash);
int    keccak_nagy_z80_hash_result  (struct hash_iface * hash, uint8_t * result);
void   keccak_nagy_z80_hash_deinit  (struct hash_iface * hash);




#endif // KECCAK_NAGY_Z80_H

