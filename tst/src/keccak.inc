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

// must be defined:
// KEBITS 8, 16, 32 or 64
// KETYPE uint8_t, uint16_t, uint32_t or uint64_t
// KEMASK 0xFFu or 0xFFFFu or 0xFFFFFFFFul or 0xFFFFFFFFFFFFFFFFull

/* -example-

  #define KETYPE uint64_t
  #define KEBITS (64)
  #define KEMASK (0xFFFFFFFFFFFFFFFFull)
*/

static KETYPE round_constants[24] = 
{
	0x0000000000000001ull & KEMASK,
	0x0000000000008082ull & KEMASK,
	0x800000000000808Aull & KEMASK,
	0x8000000080008000ull & KEMASK,
	0x000000000000808Bull & KEMASK,
	0x0000000080000001ull & KEMASK,
	0x8000000080008081ull & KEMASK,
	0x8000000000008009ull & KEMASK,
	0x000000000000008Aull & KEMASK,
	0x0000000000000088ull & KEMASK,
	0x0000000080008009ull & KEMASK,
	0x000000008000000Aull & KEMASK,
	0x000000008000808Bull & KEMASK,
	0x800000000000008Bull & KEMASK,
	0x8000000000008089ull & KEMASK,
	0x8000000000008003ull & KEMASK,
	0x8000000000008002ull & KEMASK,
	0x8000000000000080ull & KEMASK,
	0x000000000000800Aull & KEMASK,
	0x800000008000000Aull & KEMASK,
	0x8000000080008081ull & KEMASK,
	0x8000000000008080ull & KEMASK,
	0x0000000080000001ull & KEMASK,
	0x8000000080008008ull & KEMASK
};

static unsigned int rho_shifts[25] =
{
	  0 % KEBITS,
	  1 % KEBITS,
	190 % KEBITS,
	 28 % KEBITS,
	 91 % KEBITS,

	 36 % KEBITS,
	300 % KEBITS,
	  6 % KEBITS,
	 55 % KEBITS,
	276 % KEBITS,

	  3 % KEBITS,
	 10 % KEBITS,
	171 % KEBITS,
	153 % KEBITS,
	231 % KEBITS,

	105 % KEBITS,
	 45 % KEBITS,
	 15 % KEBITS,
	 21 % KEBITS,
	136 % KEBITS,

	210 % KEBITS,
	 66 % KEBITS,
	253 % KEBITS,
	120 % KEBITS,
	 78 % KEBITS
};       
         

static void keccak_theta(KETYPE * state)
{
	KETYPE p[5];
	KETYPE x[5];

	p[0] = state[ 0] ^ state[ 5] ^ state[10] ^ state[15] ^ state[20];
	p[1] = state[ 1] ^ state[ 6] ^ state[11] ^ state[16] ^ state[21];
	p[2] = state[ 2] ^ state[ 7] ^ state[12] ^ state[17] ^ state[22];
	p[3] = state[ 3] ^ state[ 8] ^ state[13] ^ state[18] ^ state[23];
	p[4] = state[ 4] ^ state[ 9] ^ state[14] ^ state[19] ^ state[24];

	x[0] = p[4] ^ (((p[1]<<1)&KEMASK) | ((p[1]>>(KEBITS-1))&KEMASK));
	x[1] = p[0] ^ (((p[2]<<1)&KEMASK) | ((p[2]>>(KEBITS-1))&KEMASK));
	x[2] = p[1] ^ (((p[3]<<1)&KEMASK) | ((p[3]>>(KEBITS-1))&KEMASK));
	x[3] = p[2] ^ (((p[4]<<1)&KEMASK) | ((p[4]>>(KEBITS-1))&KEMASK));
	x[4] = p[3] ^ (((p[0]<<1)&KEMASK) | ((p[0]>>(KEBITS-1))&KEMASK));

	for(unsigned int i=0;i<25;i+=5)
	{
		state[i+0] ^= x[0];
		state[i+1] ^= x[1];
		state[i+2] ^= x[2];
		state[i+3] ^= x[3];
		state[i+4] ^= x[4];
	}
}

static void keccak_rho(KETYPE * state)
{
	for(unsigned int i=0;i<25;i++)
	{
		state[i] = ((state[i]<<rho_shifts[i])&KEMASK) | ((state[i]>>(KEBITS-rho_shifts[i]))&KEMASK);
	}
}

static void keccak_pi(KETYPE * state)
{
/*
[x,y]->[y,2x+3y]
-----**---------
[0,0]->[0,0]
[1,0]->[0,2]
[2,0]->[0,4]
[3,0]->[0,1]
[4,0]->[0,3]
[0,1]->[1,3]
[1,1]->[1,0]
[2,1]->[1,2]
[3,1]->[1,4]
[4,1]->[1,1]
[0,2]->[2,1]
[1,2]->[2,3]
[2,2]->[2,0]
[3,2]->[2,2]
[4,2]->[2,4]
[0,3]->[3,4]
[1,3]->[3,1]
[2,3]->[3,3]
[3,3]->[3,0]
[4,3]->[3,2]
[0,4]->[4,2]
[1,4]->[4,4]
[2,4]->[4,1]
[3,4]->[4,3]
[4,4]->[4,0]
---
[ 0]->[ 0]
[ 1]->[10]
[ 2]->[20]
[ 3]->[ 5]
[ 4]->[15]
[ 5]->[16]
[ 6]->[ 1]
[ 7]->[11]
[ 8]->[21]
[ 9]->[ 6]
[10]->[ 7]
[11]->[17]
[12]->[ 2]
[13]->[12]
[14]->[22]
[15]->[23]
[16]->[ 8]
[17]->[18]
[18]->[ 3]
[19]->[13]
[20]->[14]
[21]->[24]
[22]->[ 9]
[23]->[19]
[24]->[ 4]
---
[ 0]->[ 0]
[ 1]->[10]
[10]->[ 7]
[ 7]->[11]
[11]->[17]
[17]->[18]
[18]->[ 3]
[ 3]->[ 5]
[ 5]->[16]
[16]->[ 8]
[ 8]->[21]
[21]->[24]
[24]->[ 4]
[ 4]->[15]
[15]->[23]
[23]->[19]
[19]->[13]
[13]->[12]
[12]->[ 2]
[ 2]->[20]
[20]->[14]
[14]->[22]
[22]->[ 9]
[ 9]->[ 6]
[ 6]->[ 1]
---
*/
	static unsigned int permutation[25] = 
	{
		 1,10, 7,11,17,
		18, 3, 5,16, 8,
		21,24, 4,15,23,
		19,13,12, 2,20,
		14,22, 9, 6, 1
	};

	KETYPE tmp1,tmp2;
	tmp1 = state[permutation[0]];

	for(unsigned int i=1;i<25;i++)
	{
		tmp2 = state[permutation[i]];
		state[permutation[i]] = tmp1;
		tmp1 = tmp2;
	}
}

static void keccak_chi(KETYPE * state)
{
	KETYPE nl[5];

	for(unsigned int i=0;i<25;i+=5)
	{
		nl[0] = (~state[i+1]) & state[i+2];
		nl[1] = (~state[i+2]) & state[i+3];
		nl[2] = (~state[i+3]) & state[i+4];
		nl[3] = (~state[i+4]) & state[i+0];
		nl[4] = (~state[i+0]) & state[i+1];

		state[i+0] ^= nl[0];
		state[i+1] ^= nl[1];
		state[i+2] ^= nl[2];
		state[i+3] ^= nl[3];
		state[i+4] ^= nl[4];
	}
}


static void keccak_permute_nrounds(KETYPE * state, unsigned int rounds)
{
	for(unsigned int i=0;i<rounds;i++)
	{
		keccak_theta(state);
		keccak_rho  (state);
		keccak_pi   (state);
		keccak_chi  (state);

		state[0] ^= round_constants[i];
	}
}

