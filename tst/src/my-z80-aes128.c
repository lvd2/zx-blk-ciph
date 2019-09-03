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

#include "libz80/z80.h"
#include "z80-wrap.h"

#include "ciph-common.h"
#include "my-z80-aes128.h"





static void print_state(uint8_t * state, char * name)
{
	printf("\n%s:\n--------\n",name);

	for(int i=0;i<16;i+=4)
	{
		for(int j=0;j<4;j++)
		{
			printf("%02x",state[i+j]);
		}
		printf("\n");
	}
}






static uint8_t my_aes_xtime(uint8_t x) { return 255 & ((x<<1) ^ ( (x & 0x80) ? 0x1B : 0x00)); }


static void my_aes_print_state(int round, char * prefix, uint8_t * st)
{
	printf("round[%2d].%s ",round,prefix);
	for(int i=0;i<16;i++) printf(" %02x",*(st++));
	printf("\n");
}

static void my_aes_SubBytes(struct my_z80_aes128 * aes, uint8_t * state)
{
	for(int i=0;i<16;i++)
	{
		state[i] = aes->sbox[state[i]];
	}
}

static void my_aes_InvSubBytes(struct my_z80_aes128 * aes, uint8_t * state)
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

static void my_aes_MixColumns(struct my_z80_aes128 * aes, uint8_t * state)
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

static void my_aes_InvMixColumns(struct my_z80_aes128 * aes, uint8_t * state)
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



struct ciph_iface * make_my_z80_aes128(void)
{
	static const char name[]="own Z80 aes128";

	struct ciph_iface * ciph = malloc(sizeof(struct ciph_iface));
	if( !ciph )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for ciph_iface!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	ciph->ciph_specific_data = NULL;

	ciph->name = name;

	ciph->ciph_init   = &my_z80_aes128_ciph_init;
	ciph->ciph_setkey = &my_z80_aes128_ciph_setkey;
	ciph->ciph_enc    = &my_z80_aes128_ciph_enc;
	ciph->ciph_dec    = &my_z80_aes128_ciph_dec;
	ciph->ciph_deinit = &my_z80_aes128_ciph_deinit;

	return ciph;
}





int my_z80_aes128_ciph_init(struct ciph_iface * ciph)
{ // init blowfish cipher structure

	struct my_z80_aes128 * aes = malloc(sizeof(struct my_z80_aes128));
	uint8_t x,p,q;

	struct z80_context * z80;



	if( !aes )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for struct my_z80_aes128!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}


	// create z80 context
	z80 = z80_init("z80/aes_test.bin");

	aes->z80 = z80;
	
	
	// initialize Z80 AES	
	unsigned clocks = z80_execute( z80, Z80_MAX_CLOCKS, Z80_AES_INIT );

	if( !clocks )
	{
		fprintf(stderr,"%s: %d, %s: Z80 aes init didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
		exit(1);
	}
	printf("AES: %d clocks to init (%s)\n",clocks,__func__);



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






	// check Z80-generated tables
	for(int i=0;i<256;i++)
	{
		if( z80_rdbyte(z80,Z80_SBOX_ADDR+i)!=aes->sbox[i] )
		{
			fprintf(stderr,"%s: %d, %s: error in Z80-generated sbox!\n",__FILE__,__LINE__,__FUNCTION__);
			exit(1);
		}

		if( z80_rdbyte(z80,Z80_BOX02_ADDR+i)!=aes->box02[aes->sbox[i]] )
		{
			fprintf(stderr,"%s: %d, %s: error in Z80-generated box02!\n",__FILE__,__LINE__,__FUNCTION__);
			exit(1);
		}

		if( z80_rdbyte(z80,Z80_BOX03_ADDR+i)!=aes->box03[aes->sbox[i]] )
		{
			fprintf(stderr,"%s: %d, %s: error in Z80-generated box03!\n",__FILE__,__LINE__,__FUNCTION__);
			exit(1);
		}

	}






	ciph->ciph_specific_data = (void *)aes;

	return 1;
}



int    my_z80_aes128_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size)
{
	struct my_z80_aes128 * aes = (struct my_z80_aes128 *)ciph->ciph_specific_data;

	if( key_size!=16 )
	{
		fprintf(stderr,"%s: %d, %s: key size must be 16 bytes!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}



	// Z80 setkey
	//
	// copy key to Z80 memory
	for(int i=0;i<key_size;i++)
	{
		z80_wrbyte(aes->z80,Z80_INKEY_ADDR+i,key[i]);
	}
	// run Z80 setkey
	unsigned clocks = z80_execute(aes->z80,Z80_MAX_CLOCKS, Z80_AES_SETKEY);
	if( !clocks )
	{
		fprintf(stderr,"%s: %d, %s: Z80 aes setkey didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
		exit(1);
	}
	printf("AES: %d clocks to setkey (%s)\n",clocks,__func__);







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







	// compare expanded subkeys with Z80 subkeys
	for(int i=0;i<16*(MY_AES128_ROUNDS+1);i++)
	{
		if( z80_rdbyte(aes->z80,Z80_KEYS_ADDR+i)!=aes->kw[i] )
		{
			fprintf(stderr,"%s: %d, %s: Z80 subkeys mismatch: at %02x, z80=%02x, ref=%02x!\n",__FILE__,__LINE__,__FUNCTION__,i,z80_rdbyte(aes->z80,Z80_KEYS_ADDR+i),aes->kw[i]);
			exit(1);
		}
	}






	return 1;
}



int    my_z80_aes128_ciph_enc(struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size)
{
	if( size%16 )
	{
		fprintf(stderr,"%s: %d, %s: size must be 0 mod 16!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	struct my_z80_aes128 * aes = (struct my_z80_aes128 *)ciph->ciph_specific_data;









	for(size_t block=0;block<size;block+=16)
	{
		// Z80 encrypt
		//
		// copy block to Z80 memory
		for(int i=0;i<16;i++)
		{
			z80_wrbyte(aes->z80,Z80_INDATA_ADDR+i,plain[block+i]);
		}
		// run Z80 encrypt
		unsigned clocks = z80_execute(aes->z80,Z80_MAX_CLOCKS,Z80_AES_ENCRYPT);
		if( !clocks )
		{
			fprintf(stderr,"%s: %d, %s: Z80 aes encrypt didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
			exit(1);
		}
		printf("AES: %d clocks to encrypt (%s)\n",clocks,__func__);




		uint8_t * kw = aes->kw;

		uint8_t * state = &cipher[block];
		memcpy(state,&plain[block],16);
		
		// initial AddRoundKey
		for(int j=0;j<16;j++)
			state[j] ^= *(kw++);
		my_aes_ShiftRows(state);




		// normal rounds
		for(int i=1;i<MY_AES128_ROUNDS;i++)
		{
			my_aes_SubBytes(aes,state);
			my_aes_MixColumns(aes,state);
			
			// AddRoundKey
			for(int k=0;k<16;k++)
				state[k] ^= *(kw++);
			
			my_aes_ShiftRows(state);
		}


		my_aes_SubBytes(aes,state);
		// final AddRoundKey
		for(int k=0;k<16;k++)
			state[k] ^= *(kw++);


		// compare encrypted data to Z80 results
		for(int i=0;i<16;i++)
		{
			if( state[i]!=z80_rdbyte(aes->z80,Z80_OUTDATA_ADDR+i) )
			{
				fprintf(stderr,"%s: %d, %s: Z80 encrypt mismatch: at %02x, z80=%02x, ref=%02x!\n",__FILE__,__LINE__,__FUNCTION__,i,z80_rdbyte(aes->z80,Z80_OUTDATA_ADDR+i),state[i]);
				exit(1);
			}
		}

	};

	return 1;
}

int    my_z80_aes128_ciph_dec(struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size)
{
	if( size%16 )
	{
		fprintf(stderr,"%s: %d, %s: size must be 0 mod 16!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	struct my_z80_aes128 * aes = (struct my_z80_aes128 *)ciph->ciph_specific_data;


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
			my_aes_InvSubBytes(aes,state);
			my_aes_InvShiftRows(state);
			my_aes_InvMixColumns(aes,state);

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

void   my_z80_aes128_ciph_deinit(struct ciph_iface * ciph)
{
	if( ciph->ciph_specific_data )
	{
		struct my_z80_aes128 * aes = (struct my_z80_aes128 *)ciph->ciph_specific_data;

		if( aes->z80 )
		{
			free( aes->z80 );
			aes->z80 = NULL;
		}

		free( ciph->ciph_specific_data );
	}
	
	ciph->ciph_specific_data = NULL;
}










