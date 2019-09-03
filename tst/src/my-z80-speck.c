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
#include "my-z80-speck.h"



static uint64_t speck_encrypt(struct my_z80_speck * speck, uint64_t plaintext );
static uint64_t speck_decrypt(struct my_z80_speck * speck, uint64_t ciphertext);

static void speck_round(uint32_t * x, uint32_t * y, uint32_t k);
static void speck_iround(uint32_t * x, uint32_t * y, uint32_t k);









struct ciph_iface * make_my_z80_speck(void)
{
	static const char name[]="own Z80 speck";

	struct ciph_iface * ciph = malloc(sizeof(struct ciph_iface));
	if( !ciph )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for ciph_iface!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	ciph->ciph_specific_data = NULL;

	ciph->name = name;

	ciph->ciph_init   = &my_z80_speck_ciph_init;
	ciph->ciph_setkey = &my_z80_speck_ciph_setkey;
	ciph->ciph_enc    = &my_z80_speck_ciph_enc;
	ciph->ciph_dec    = &my_z80_speck_ciph_dec;
	ciph->ciph_deinit = &my_z80_speck_ciph_deinit;

	return ciph;
}





int my_z80_speck_ciph_init(struct ciph_iface * ciph)
{ // init speck cipher structure

	struct my_z80_speck * speck = malloc(sizeof(struct my_z80_speck));

	struct z80_context * z80;


	if( !speck )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for struct my_z80_speck!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	ciph->ciph_specific_data = (void *)speck;





	// load Z80 binary
	z80=z80_init("z80/speck_test.bin");
	
	speck->z80 = z80;




	//
	unsigned clocks = z80_execute(z80, Z80_MAX_CLOCKS, Z80_SP_INIT);
	if( !clocks )
	{
		fprintf(stderr,"%s: %d, %s: Z80 speck init didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
		exit(1);
	}
	printf("SPECK: %d clocks to init (%s)\n",clocks,__func__);






	return 1;
}



int    my_z80_speck_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size)
{
	struct my_z80_speck * speck = (struct my_z80_speck *)ciph->ciph_specific_data;

	if( key_size!=16 )
	{
		fprintf(stderr,"%s: %d, %s: key size must be 16 bytes!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}


	uint32_t a;
	uint32_t b[3];
	uint32_t bptr=0;

	a = (*(uint32_t *)&key[0]);
	b[0] = (*(uint32_t *)&key[4]);
	b[1] = (*(uint32_t *)&key[8]);
	b[2] = (*(uint32_t *)&key[12]);

	for(int i=0;i<MY_SPECK_ROUNDS-1;i++)
	{
//printf("keying[%d]  input: L=%08x, R=%08x\n",i,b[bptr],a);
		speck->k[i] = a; speck_round(&b[bptr],&a,i);
//printf("keying[%d] output: L=%08x, R=%08x\n",i,b[bptr],a);
		bptr = (bptr>=2)?0:(bptr+1);
	}

	speck->k[MY_SPECK_ROUNDS-1] = a;
//for(int i=0;i<MY_SPECK_ROUNDS;i++)
//printf("rk[%d]=%08x\n",i,speck->k[i]);

	
	// run Z80 subkey generation
	//
	// copy key to Z80 memory
	for(int i=0;i<key_size;i++)
	{
		z80_wrbyte(speck->z80,Z80_SP_INKEY_ADDR+i,key[i]);
	}
	// run Z80 setkey
	unsigned clocks = z80_execute(speck->z80, Z80_MAX_CLOCKS, Z80_SP_SETKEY);
	if( !clocks )
	{
		fprintf(stderr,"%s: %d, %s: Z80 speck setkey didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
		fprintf(stderr,"pc=%04x\n",speck->z80->z80.PC);
		exit(1);
	}
	printf("SPECK: %d clocks to setkey (%s)\n",clocks,__func__);

//printf("Z80 speck state:\n");
//for(int i=0;i<MY_SPECK_ROUNDS*4;i+=4)
// printf("rk[%d]=%08x\n",i/4,*(uint32_t *)&z80_mem[Z80_SP_KEYS_ADDR+i]);
//printf("\n");


	// check z80-generated subkeys
	for(int i=0;i<MY_SPECK_ROUNDS*4;i+=4)
	{
		uint32_t z80 = z80_rdlong_le(speck->z80,Z80_SP_KEYS_ADDR+i);
		uint32_t key = speck->k[i/4];

		if( z80!=key )
		{
			fprintf(stderr,"%s: key check: at %d, z80=%08x, tbl=%08x\n",__func__,i,z80,key);
			exit(1);
		}
	}



	return 1;
}



int    my_z80_speck_ciph_enc(struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size)
{
	struct my_z80_speck * speck = (struct my_z80_speck *)ciph->ciph_specific_data;
	
	if( size%8 )
	{
		fprintf(stderr,"%s: %d, %s: size must be 0 mod 8!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	for(size_t i=0;i<size;i+=8)
	{
		*(uint64_t *)&cipher[i] = speck_encrypt(((struct my_z80_speck *)ciph->ciph_specific_data),*(uint64_t *)&plain[i]);


		// run Z80 encryption
		// copy data to Z80 memory
		for(int j=0;j<8;j++)
		{
			z80_wrbyte(speck->z80,Z80_SP_INDATA_ADDR+j,plain[i+j]);
		}
		// run Z80 code
		unsigned clocks = z80_execute(speck->z80, Z80_MAX_CLOCKS, Z80_SP_ENCRYPT);
		if( !clocks )
		{
			fprintf(stderr,"%s: %d, %s: Z80 speck encrypt didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
			fprintf(stderr,"pc=%04x\n",speck->z80->z80.PC);
			exit(1);
		}
		printf("SPECK: %d clocks to encrypt (%s)\n",clocks,__func__);
//printf("Z80 speck state: %08x %08x\n",*(uint32_t *)&z80_mem[Z80_SP_STATE_ADDR+4],*(uint32_t *)&z80_mem[Z80_SP_STATE_ADDR+0]);

		// compare Z80 results with reference
		uint64_t z80 = z80_rdocta_le(speck->z80,Z80_SP_OUTDATA_ADDR);
		uint64_t ref = *(uint64_t *)&cipher[i];

		if( z80!=ref )
		{
			fprintf(stderr,"%s: Z80 failed: z80=%016lx,ref=%016lx\n",__func__,z80,ref);
			exit(1);
		}

	}

	return 1;
}

int    my_z80_speck_ciph_dec(struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size)
{
	if( size%8 )
	{
		fprintf(stderr,"%s: %d, %s: size must be 0 mod 8!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	for(size_t i=0;i<size;i+=8)
	{
		*(uint64_t *)&plain[i] = speck_decrypt(((struct my_z80_speck *)ciph->ciph_specific_data),*(uint64_t *)&cipher[i]);
	}

	return 1;
}

void   my_z80_speck_ciph_deinit(struct ciph_iface * ciph)
{
	if( ciph->ciph_specific_data )
		free( ciph->ciph_specific_data );
	
	ciph->ciph_specific_data = NULL;
}






static uint64_t speck_encrypt(struct my_z80_speck * speck, uint64_t plaintext )
{
	uint32_t x = plaintext>>32;
	uint32_t y = plaintext & 0xFFFFFFFFULL;

//printf("Pt_%d=(%08x,%08x)\n",0,x,y);
	for(int i=0;i<MY_SPECK_ROUNDS;i++)
	{
		speck_round( &x, &y, speck->k[i] );
//printf("Pt_%d=(%08x,%08x)\n",i+1,x,y);
	}

	return (((uint64_t)x)<<32) | (((uint64_t)y)&0xFFFFFFFFULL);
}

static uint64_t speck_decrypt(struct my_z80_speck * speck, uint64_t ciphertext)
{
	uint32_t x = ciphertext>>32;
	uint32_t y = ciphertext & 0xFFFFFFFFULL;

//printf("Pt_%d=(%08x,%08x)\n",0,x,y);
	for(int i=(MY_SPECK_ROUNDS-1);i>=0;i--)
	{
		speck_iround( &x, &y, speck->k[i] );
//printf("Pt_%d=(%08x,%08x)\n",i+1,x,y);
	}

	return (((uint64_t)x)<<32) | (((uint64_t)y)&0xFFFFFFFFULL);
}


static void speck_round(uint32_t * x, uint32_t * y, uint32_t k)
{
	*x = ((*x)>>8) | ((*x)<<24); // ROR 8
//printf("Lror8 = %08x\n",*x);
	*x += *y;
//printf("L+R   = %08x\n",*x);
	*x ^= k;
//printf("LxorK = %08x\n",*x);
	*y = ((*y)<<3) | ((*y)>>29); // ROL 3
//printf("Rrol3 = %08x\n",*y);
	*y ^= *x;
//printf("RxorL = %08x\n",*y);
}

static void speck_iround(uint32_t * x, uint32_t * y, uint32_t k)
{
	*y ^= *x;

	*y = ((*y)>>3) | ((*y)<<29); // ROR 3

	*x ^= k;

	*x -= *y;

	*x = ((*x)<<8) | ((*x)>>24); // ROL 8
}



