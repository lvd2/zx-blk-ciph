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
#include "my-c-speck.h"



static uint64_t speck_encrypt(struct my_c_speck * speck, uint64_t plaintext );
static uint64_t speck_decrypt(struct my_c_speck * speck, uint64_t ciphertext);

static void speck_round(uint32_t * x, uint32_t * y, uint32_t k);
static void speck_iround(uint32_t * x, uint32_t * y, uint32_t k);



struct ciph_iface * make_my_c_speck(void)
{
	static const char name[]="own C speck";

	struct ciph_iface * ciph = malloc(sizeof(struct ciph_iface));
	if( !ciph )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for ciph_iface!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	ciph->ciph_specific_data = NULL;

	ciph->name = name;

	ciph->ciph_init   = &my_c_speck_ciph_init;
	ciph->ciph_setkey = &my_c_speck_ciph_setkey;
	ciph->ciph_enc    = &my_c_speck_ciph_enc;
	ciph->ciph_dec    = &my_c_speck_ciph_dec;
	ciph->ciph_deinit = &my_c_speck_ciph_deinit;

	return ciph;
}





int my_c_speck_ciph_init(struct ciph_iface * ciph)
{ // init speck cipher structure

	struct my_c_speck * speck = malloc(sizeof(struct my_c_speck));

	if( !speck )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for struct my_c_speck!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	ciph->ciph_specific_data = (void *)speck;

	return 1;
}



int    my_c_speck_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size)
{
	struct my_c_speck * speck = (struct my_c_speck *)ciph->ciph_specific_data;

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
		speck->k[i] = a; speck_round(&b[bptr],&a,i);
		bptr = (bptr>=2)?0:(bptr+1);
	}

	speck->k[MY_SPECK_ROUNDS-1] = a;


//for(int i=0;i<MY_SPECK_ROUNDS;i++)
//printf("rk[%d]=%08x\n",i,speck->k[i]);



	return 1;
}



int    my_c_speck_ciph_enc(struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size)
{
	if( size%8 )
	{
		fprintf(stderr,"%s: %d, %s: size must be 0 mod 8!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	for(size_t i=0;i<size;i+=8)
	{
		*(uint64_t *)&cipher[i] = speck_encrypt(((struct my_c_speck *)ciph->ciph_specific_data),*(uint64_t *)&plain[i]);
	}

	return 1;
}

int    my_c_speck_ciph_dec(struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size)
{
	if( size%8 )
	{
		fprintf(stderr,"%s: %d, %s: size must be 0 mod 8!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	for(size_t i=0;i<size;i+=8)
	{
		*(uint64_t *)&plain[i] = speck_decrypt(((struct my_c_speck *)ciph->ciph_specific_data),*(uint64_t *)&cipher[i]);
	}

	return 1;
}

void   my_c_speck_ciph_deinit(struct ciph_iface * ciph)
{
	if( ciph->ciph_specific_data )
		free( ciph->ciph_specific_data );
	
	ciph->ciph_specific_data = NULL;
}






static uint64_t speck_encrypt(struct my_c_speck * speck, uint64_t plaintext )
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

static uint64_t speck_decrypt(struct my_c_speck * speck, uint64_t ciphertext)
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

	*x += *y;

	*x ^= k;

	*y = ((*y)<<3) | ((*y)>>29); // ROL 3

	*y ^= *x;
}

static void speck_iround(uint32_t * x, uint32_t * y, uint32_t k)
{
	*y ^= *x;

	*y = ((*y)>>3) | ((*y)<<29); // ROR 3

	*x ^= k;

	*x -= *y;

	*x = ((*x)<<8) | ((*x)>>24); // ROL 8
}



