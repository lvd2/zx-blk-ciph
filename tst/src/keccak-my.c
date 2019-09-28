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

#include "hash-common.h"
#include "keccak-my.h"



#define KETYPE uint64_t
#define KEBITS (64)
#define KEMASK (0xFFFFFFFFFFFFFFFFull)

#include "keccak.inc"




struct hash_iface * make_keccak_my(void)
{
	static const char name[]="own C keccak";

	struct hash_iface * hash = malloc(sizeof(struct hash_iface));
	if( !hash )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for hash_iface!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	hash->hash_specific_data = NULL;

	hash->name = name;

	hash->hash_init     = &keccak_my_hash_init;
	hash->hash_start    = &keccak_my_hash_start;
	hash->hash_addbytes = &keccak_my_hash_addbytes;
	hash->hash_getsize  = &keccak_my_hash_getsize;
	hash->hash_result   = &keccak_my_hash_result;
	hash->hash_deinit   = &keccak_my_hash_deinit;

	return hash;
}


int    keccak_my_hash_init    (struct hash_iface * hash)
{
	struct my_keccak * keccak = malloc(sizeof(struct my_keccak));
	if( !keccak )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for my_keccak!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	hash->hash_specific_data = (void *)keccak;

	return 1;
}

int    keccak_my_hash_start   (struct hash_iface * hash)
{
	struct my_keccak * keccak = (struct my_keccak *)hash->hash_specific_data;

	keccak->pos = 0;
	
	for(unsigned int i=0;i<25;i++)
		keccak->state[i] = 0;

	return 1;
}

int    keccak_my_hash_addbytes(struct hash_iface * hash, uint8_t * message, size_t size)
{
	struct my_keccak * keccak = (struct my_keccak *)hash->hash_specific_data;

	size_t curr_size;

	uint8_t * state = (uint8_t *)keccak->state;


	while( size>0 )
	{
		curr_size = MY_KECCAK_RATE - keccak->pos;
		if( curr_size>size ) curr_size = size;


		for(unsigned int i=0;i<curr_size;i++)
		{
			state[keccak->pos++] ^= *(message++);
		}

		size -= curr_size;

		if( keccak->pos >= MY_KECCAK_RATE )
		{
			keccak->pos = 0;
			keccak_permute_nrounds(keccak->state,24);
		}
	}


	return 1;
}

size_t keccak_my_hash_getsize (struct hash_iface * hash)
{
	return 32;
}

int    keccak_my_hash_result  (struct hash_iface * hash, uint8_t * result)
{
	struct my_keccak * keccak = (struct my_keccak *)hash->hash_specific_data;

	uint8_t * state = (uint8_t *)keccak->state;
	

	state[keccak->pos     ] ^= 0x01;
	state[MY_KECCAK_RATE-1] ^= 0x80;

	keccak_permute_nrounds(keccak->state,24);

	memcpy(result,state,32);


	return 1;
}


void   keccak_my_hash_deinit  (struct hash_iface * hash)
{
	if( hash->hash_specific_data )
	{
		free(hash->hash_specific_data);
		hash->hash_specific_data = NULL;
	}
}





