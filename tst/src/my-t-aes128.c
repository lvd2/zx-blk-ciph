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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ciph-common.h"
#include "my-t-aes128.h"



static uint8_t my_aes_xtime(uint8_t x) { return 255 & ((x<<1) ^ ( (x & 0x80) ? 0x1B : 0x00)); }


static void my_aes_print_state(int round, char * prefix, uint8_t * st)
{
	printf("round[%2d].%s ",round,prefix);
	for(int i=0;i<16;i++) printf(" %02x",*(st++));
	printf("\n");
}

static void my_aes_SubBytes(struct my_t_aes128 * aes, uint8_t * state)
{
	for(int i=0;i<16;i++)
	{
		state[i] = aes->sbox[state[i]];
	}
}

static void my_aes_InvSubBytes(struct my_t_aes128 * aes, uint8_t * state)
{
	for(int i=0;i<16;i++)
	{
		state[i] = aes->ibox[state[i]];
	}
}

static void my_aes_ShiftRows(uint8_t * state)
{
	// 00 04 08 12    00 04 08 12
	// 01 05 09 13 => 05 09 13 01
	// 02 06 10 14    10 14 02 06
	// 03 07 11 15    15 03 07 11
	
	uint8_t tmp[16];
	memcpy(tmp,state,16);

	state[ 0]=tmp[ 0]; state[ 4]=tmp[ 4]; state[ 8]=tmp[ 8]; state[12]=tmp[12];
	state[ 1]=tmp[ 5]; state[ 5]=tmp[ 9]; state[ 9]=tmp[13]; state[13]=tmp[ 1];
	state[ 2]=tmp[10]; state[ 6]=tmp[14]; state[10]=tmp[ 2]; state[14]=tmp[ 6];
	state[ 3]=tmp[15]; state[ 7]=tmp[ 3]; state[11]=tmp[ 7]; state[15]=tmp[11];
}

static void my_aes_InvShiftRows(uint8_t * state)
{
	// 00 04 08 12    00 04 08 12
	// 05 09 13 01 => 01 05 09 13
	// 10 14 02 06    02 06 10 14
	// 15 03 07 11    03 07 11 15
	
	uint8_t tmp[16];
	memcpy(tmp,state,16);

	state[ 0]=tmp[ 0]; state[ 4]=tmp[ 4]; state[ 8]=tmp[ 8]; state[12]=tmp[12];
	state[ 5]=tmp[ 1]; state[ 9]=tmp[ 5]; state[13]=tmp[ 9]; state[ 1]=tmp[13];
	state[10]=tmp[ 2]; state[14]=tmp[ 6]; state[ 2]=tmp[10]; state[ 6]=tmp[14];
	state[15]=tmp[ 3]; state[ 3]=tmp[ 7]; state[ 7]=tmp[11]; state[11]=tmp[15];
}

static void my_aes_MixColumns(struct my_t_aes128 * aes, uint8_t * state)
{
	uint8_t t[4];

	for(int i=0;i<16;i+=4)
	{
		t[0] = aes->box02[state[i+0]] ^ aes->box03[state[i+1]] ^            state[i+2]  ^            state[i+3] ;
		t[1] =            state[i+0]  ^ aes->box02[state[i+1]] ^ aes->box03[state[i+2]] ^            state[i+3] ;
		t[2] =            state[i+0]  ^            state[i+1]  ^ aes->box02[state[i+2]] ^ aes->box03[state[i+3]];
		t[3] = aes->box03[state[i+0]] ^            state[i+1]  ^            state[i+2]  ^ aes->box02[state[i+3]];

		state[i+0] = t[0];
		state[i+1] = t[1];
		state[i+2] = t[2];
		state[i+3] = t[3];
	}
}

static void my_aes_InvMixColumns(struct my_t_aes128 * aes, uint8_t * state)
{
	uint8_t t[4];

	for(int i=0;i<16;i+=4)
	{
		t[0] = aes->box0E[state[i+0]] ^ aes->box0B[state[i+1]] ^ aes->box0D[state[i+2]] ^ aes->box09[state[i+3]];
		t[1] = aes->box09[state[i+0]] ^ aes->box0E[state[i+1]] ^ aes->box0B[state[i+2]] ^ aes->box0D[state[i+3]];
		t[2] = aes->box0D[state[i+0]] ^ aes->box09[state[i+1]] ^ aes->box0E[state[i+2]] ^ aes->box0B[state[i+3]];
		t[3] = aes->box0B[state[i+0]] ^ aes->box0D[state[i+1]] ^ aes->box09[state[i+2]] ^ aes->box0E[state[i+3]];

		state[i+0] = t[0];
		state[i+1] = t[1];
		state[i+2] = t[2];
		state[i+3] = t[3];
	}
}



struct ciph_iface * make_my_t_aes128(void)
{
	static const char name[]="own T aes128";

	struct ciph_iface * ciph = malloc(sizeof(struct ciph_iface));
	if( !ciph )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for ciph_iface!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	ciph->ciph_specific_data = NULL;

	ciph->name = name;

	ciph->ciph_init   = &my_t_aes128_ciph_init;
	ciph->ciph_setkey = &my_t_aes128_ciph_setkey;
	ciph->ciph_enc    = &my_t_aes128_ciph_enc;
	ciph->ciph_dec    = &my_t_aes128_ciph_dec;
	ciph->ciph_deinit = &my_t_aes128_ciph_deinit;

	return ciph;
}





int my_t_aes128_ciph_init(struct ciph_iface * ciph)
{ // init blowfish cipher structure

	struct my_t_aes128 * aes = malloc(sizeof(struct my_t_aes128));
	uint8_t x,p,q;

	if( !aes )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for struct my_t_aes128!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	// make multiplying boxes
	x=0;
	do
	{
		uint8_t x1 = my_aes_xtime(x);
		uint8_t x2 = my_aes_xtime(x1);
		uint8_t x3 = my_aes_xtime(x2);

		aes->box02[x] =           x1    ;
		aes->box03[x] =           x1 ^ x;
		aes->box09[x] = x3 ^           x;
		aes->box0B[x] = x3 ^      x1 ^ x;
		aes->box0D[x] = x3 ^ x2      ^ x;
		aes->box0E[x] = x3 ^ x2 ^ x1    ;

	} while( (++x)&255 );

	// generate sbox and ibox
	p=q=1;
	do
	{
		p = my_aes_xtime(p) ^ p;

		q ^= 255 & (q<<1);
		q ^= 255 & (q<<2);
		q ^= 255 & (q<<4);
		q ^= (q&0x80) ? 0x09 : 0x00;

		x = 255 & (q ^ ((q<<1) | (q>>7)) ^ ((q<<2) | (q>>6)) ^ ((q<<3) | (q>>5)) ^ ((q<<4) | (q>>4)));
		x ^= 0x63;

		aes->sbox[p] = x;
		aes->ibox[x] = p;
//printf("sbox[%02x]=%02x\n",p,x);
	} while(p!=1);
	//
	aes->sbox[0x00] = 0x63;
	aes->ibox[0x63] = 0x00;


	// generate 32bit s02010103 and i0E090D0B
	for(int i=0;i<256;i++)
	{
		uint8_t * wr;
	       
		wr = (uint8_t *)&aes->box_s02010103[i];
		//
		wr[0] = aes->box02[aes->sbox[i]];
		wr[1] =            aes->sbox[i] ;
		wr[2] =            aes->sbox[i] ;
		wr[3] = aes->box03[aes->sbox[i]];

		wr = (uint8_t *)&aes->box_i0E090D0B[i];
		//
		wr[0] = aes->box0E[aes->ibox[i]];
		wr[1] = aes->box09[aes->ibox[i]];
		wr[2] = aes->box0D[aes->ibox[i]];
		wr[3] = aes->box0B[aes->ibox[i]];
	}




	ciph->ciph_specific_data = (void *)aes;

	return 1;
}



int    my_t_aes128_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size)
{
	struct my_t_aes128 * aes = (struct my_t_aes128 *)ciph->ciph_specific_data;

	if( key_size!=16 )
	{
		fprintf(stderr,"%s: %d, %s: key size must be 16 bytes!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	// expand key to kw
	for(int i=0;i<16;i++)
	{
		aes->kw[i] = key[i];
	}
	//
	// expand past key size
	uint8_t rc=0x01;
	for(int i=key_size/4;i<4*(MY_AES128_ROUNDS+1);i++)
	{
		uint8_t temp[4];
//printf("i=%02d ",i);
		temp[0] = aes->kw[4*(i-1)+0];
		temp[1] = aes->kw[4*(i-1)+1];
		temp[2] = aes->kw[4*(i-1)+2];
		temp[3] = aes->kw[4*(i-1)+3];
//printf("temp=%02x%02x%02x%02x ",temp[0],temp[1],temp[2],temp[3]);
		if( ! (/*i%(key_size>>2)*/ i%4) )
		{
			// RotWord
			uint8_t tmp = temp[0];
			temp[0] = temp[1];
			temp[1] = temp[2];
			temp[2] = temp[3];
			temp[3] = tmp;
//printf("RotWord=%02x%02x%02x%02x ",temp[0],temp[1],temp[2],temp[3]);
			// SubWord
			temp[0] = aes->sbox[temp[0]];
			temp[1] = aes->sbox[temp[1]];
			temp[2] = aes->sbox[temp[2]];
			temp[3] = aes->sbox[temp[3]];
//printf("SubWord=%02x%02x%02x%02x ",temp[0],temp[1],temp[2],temp[3]);
			// Rcon
			temp[0] ^= rc;
//printf("Rcon=%02x%02x%02x%02x ",temp[0],temp[1],temp[2],temp[3]);
			// Rcon update
			rc = my_aes_xtime(rc);
		}
//		else
//			printf("                                                ");

		aes->kw[4*i+0] = aes->kw[4*i-key_size+0] ^ temp[0];
		aes->kw[4*i+1] = aes->kw[4*i-key_size+1] ^ temp[1];
		aes->kw[4*i+2] = aes->kw[4*i-key_size+2] ^ temp[2];
		aes->kw[4*i+3] = aes->kw[4*i-key_size+3] ^ temp[3];
//printf("w[i]=%02x%02x%02x%02x\n",aes->kw[4*i+0],aes->kw[4*i+1],aes->kw[4*i+2],aes->kw[4*i+3]);
	}


	// make decryption key (for equivalent decipher)
	//
	for(int i=0;i<16*(MY_AES128_ROUNDS+1);i+=16)
	{ // reverse order of subkeys
		int j = 16*MY_AES128_ROUNDS - i;

		memcpy( &aes->dw[j], &aes->kw[i], 16 );
	}
	//
	for(int i=16;i<16*MY_AES128_ROUNDS;i+=16)
	{ // apply InvMixColumns to every vector in subkeys except first and last
		
		my_aes_InvMixColumns( aes, &aes->dw[i] );
	}

	return 1;
}



int    my_t_aes128_ciph_enc(struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size)
{
	if( size%16 )
	{
		fprintf(stderr,"%s: %d, %s: size must be 0 mod 16!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	struct my_t_aes128 * aes = (struct my_t_aes128 *)ciph->ciph_specific_data;


	for(size_t block=0;block<size;block+=16)
	{
		uint8_t * kw = aes->kw;

		uint8_t * state = &cipher[block];
		memcpy(state,&plain[block],16);
		
		// initial AddRoundKey
		for(int j=0;j<16;j++)
			state[j] ^= *(kw++);

		// normal rounds
		for(int i=1;i<MY_AES128_ROUNDS;i++)
		{
//			my_aes_SubBytes(aes,state);
//			my_aes_ShiftRows(state);
//			my_aes_MixColumns(aes,state);

			uint32_t word[16];


			word[ 0] = aes->box_s02010103[state[ 0]];
			word[ 1] = aes->box_s02010103[state[ 5]];
			word[ 2] = aes->box_s02010103[state[10]];
			word[ 3] = aes->box_s02010103[state[15]];

			word[ 4] = aes->box_s02010103[state[ 4]];
			word[ 5] = aes->box_s02010103[state[ 9]];
			word[ 6] = aes->box_s02010103[state[14]];
			word[ 7] = aes->box_s02010103[state[ 3]];

			word[ 8] = aes->box_s02010103[state[ 8]];
			word[ 9] = aes->box_s02010103[state[13]];
			word[10] = aes->box_s02010103[state[ 2]];
			word[11] = aes->box_s02010103[state[ 7]];

			word[12] = aes->box_s02010103[state[12]];
			word[13] = aes->box_s02010103[state[ 1]];
			word[14] = aes->box_s02010103[state[ 6]];
			word[15] = aes->box_s02010103[state[11]];


			word[ 1] = (word[ 1]<< 8)|(word[ 1]>>24);
			word[ 5] = (word[ 5]<< 8)|(word[ 5]>>24);
			word[ 9] = (word[ 9]<< 8)|(word[ 9]>>24);
			word[13] = (word[13]<< 8)|(word[13]>>24);

			word[ 2] = (word[ 2]<<16)|(word[ 2]>>16);
			word[ 6] = (word[ 6]<<16)|(word[ 6]>>16);
			word[10] = (word[10]<<16)|(word[10]>>16);
			word[14] = (word[14]<<16)|(word[14]>>16);

			word[ 3] = (word[ 3]<<24)|(word[ 3]>> 8);
			word[ 7] = (word[ 7]<<24)|(word[ 7]>> 8);
			word[11] = (word[11]<<24)|(word[11]>> 8);
			word[15] = (word[15]<<24)|(word[15]>> 8);


			*(uint32_t *)&state[ 0] = word[ 0] ^ word[ 1] ^ word[ 2] ^ word[ 3];
			*(uint32_t *)&state[ 4] = word[ 4] ^ word[ 5] ^ word[ 6] ^ word[ 7];
			*(uint32_t *)&state[ 8] = word[ 8] ^ word[ 9] ^ word[10] ^ word[11];
			*(uint32_t *)&state[12] = word[12] ^ word[13] ^ word[14] ^ word[15];


			// AddRoundKey
			for(int k=0;k<16;k++)
				state[k] ^= *(kw++);
		}

		my_aes_SubBytes(aes,state);
		my_aes_ShiftRows(state);
		// final AddRoundKey
		for(int k=0;k<16;k++)
			state[k] ^= *(kw++);
	};

	return 1;
}

int    my_t_aes128_ciph_dec(struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size)
{
	if( size%16 )
	{
		fprintf(stderr,"%s: %d, %s: size must be 0 mod 16!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	struct my_t_aes128 * aes = (struct my_t_aes128 *)ciph->ciph_specific_data;


	for(size_t block=0;block<size;block+=16)
	{
		uint8_t * dw = aes->dw;

		uint8_t * state = &plain[block];
		memcpy(state,&cipher[block],16);

		// initial InvAddRoundKey
		for(int j=0;j<16;j++)
			state[j] ^= *(dw++);

		// normal rounds
		for(int i=1;i<MY_AES128_ROUNDS;i++)
		{
//			my_aes_InvSubBytes(aes,state);
//			my_aes_InvShiftRows(state);
//			my_aes_InvMixColumns(aes,state);

			uint32_t word[16];


			word[ 0] = aes->box_i0E090D0B[state[ 0]];
			word[ 1] = aes->box_i0E090D0B[state[13]];
			word[ 2] = aes->box_i0E090D0B[state[10]];
			word[ 3] = aes->box_i0E090D0B[state[ 7]];

			word[ 4] = aes->box_i0E090D0B[state[ 4]];
			word[ 5] = aes->box_i0E090D0B[state[ 1]];
			word[ 6] = aes->box_i0E090D0B[state[14]];
			word[ 7] = aes->box_i0E090D0B[state[11]];

			word[ 8] = aes->box_i0E090D0B[state[ 8]];
			word[ 9] = aes->box_i0E090D0B[state[ 5]];
			word[10] = aes->box_i0E090D0B[state[ 2]];
			word[11] = aes->box_i0E090D0B[state[15]];

			word[12] = aes->box_i0E090D0B[state[12]];
			word[13] = aes->box_i0E090D0B[state[ 9]];
			word[14] = aes->box_i0E090D0B[state[ 6]];
			word[15] = aes->box_i0E090D0B[state[ 3]];


			word[ 1] = (word[ 1]<< 8)|(word[ 1]>>24);
			word[ 5] = (word[ 5]<< 8)|(word[ 5]>>24);
			word[ 9] = (word[ 9]<< 8)|(word[ 9]>>24);
			word[13] = (word[13]<< 8)|(word[13]>>24);

			word[ 2] = (word[ 2]<<16)|(word[ 2]>>16);
			word[ 6] = (word[ 6]<<16)|(word[ 6]>>16);
			word[10] = (word[10]<<16)|(word[10]>>16);
			word[14] = (word[14]<<16)|(word[14]>>16);

			word[ 3] = (word[ 3]<<24)|(word[ 3]>> 8);
			word[ 7] = (word[ 7]<<24)|(word[ 7]>> 8);
			word[11] = (word[11]<<24)|(word[11]>> 8);
			word[15] = (word[15]<<24)|(word[15]>> 8);


			*(uint32_t *)&state[ 0] = word[ 0] ^ word[ 1] ^ word[ 2] ^ word[ 3];
			*(uint32_t *)&state[ 4] = word[ 4] ^ word[ 5] ^ word[ 6] ^ word[ 7];
			*(uint32_t *)&state[ 8] = word[ 8] ^ word[ 9] ^ word[10] ^ word[11];
			*(uint32_t *)&state[12] = word[12] ^ word[13] ^ word[14] ^ word[15];


			// AddRoundKey
			for(int k=0;k<16;k++)
				state[k] ^= *(dw++);

		}
		my_aes_InvSubBytes(aes,state);
		my_aes_InvShiftRows(state);

		// final AddRoundKey
		for(int k=0;k<16;k++)
			state[k] ^= *(dw++);

	};

	return 1;
}

void   my_t_aes128_ciph_deinit(struct ciph_iface * ciph)
{
	if( ciph->ciph_specific_data )
		free( ciph->ciph_specific_data );
	
	ciph->ciph_specific_data = NULL;
}










