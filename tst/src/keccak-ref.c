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

#include "libkeccak/KeccakHash.h"

#include "hash-common.h"
#include "keccak-ref.h"



struct hash_iface * make_keccak_ref(void)
{
	static const char name[]="reference libkeccak";

	struct hash_iface * hash = malloc(sizeof(struct hash_iface));
	if( !hash )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for hash_iface!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	hash->hash_specific_data = NULL;

	hash->name = name;

	hash->hash_init     = &keccak_ref_hash_init;
	hash->hash_start    = &keccak_ref_hash_start;
	hash->hash_addbytes = &keccak_ref_hash_addbytes;
	hash->hash_getsize  = &keccak_ref_hash_getsize;
	hash->hash_result   = &keccak_ref_hash_result;
	hash->hash_deinit   = &keccak_ref_hash_deinit;

	return hash;
}


int    keccak_ref_hash_init    (struct hash_iface * hash)
{
	Keccak_HashInstance * instance = malloc(sizeof(Keccak_HashInstance));
	if( !instance )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for Keccak_HashInstance!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	hash->hash_specific_data = (void *)instance;

	return 1;
}

int    keccak_ref_hash_start   (struct hash_iface * hash)
{
	Keccak_HashInstance * instance = (Keccak_HashInstance *)hash->hash_specific_data;
	int e;

	if( (e=Keccak_HashInitialize(instance, 1088, 512, 256, 0x01)) )
	{
		fprintf(stderr,"%s: %d, %s: can't initialize Keccak_HashInstance! Error=%d\n",__FILE__,__LINE__,__func__,e);
		exit(1);
	}

	return 1;
}

int    keccak_ref_hash_addbytes(struct hash_iface * hash, uint8_t * message, size_t size)
{
	Keccak_HashInstance * instance = (Keccak_HashInstance *)hash->hash_specific_data;
	int e;
	
	if( (e=Keccak_HashUpdate(instance, message, size*8)) )
	{
		fprintf(stderr,"%s: %d, %s: can't run Keccak_HashUpdate! Error=%d\n",__FILE__,__LINE__,__func__,e);
		exit(1);
	}

	return 1;
}

size_t keccak_ref_hash_getsize (struct hash_iface * hash)
{
	return 32;
}

int    keccak_ref_hash_result  (struct hash_iface * hash, uint8_t * result)
{
	Keccak_HashInstance * instance = (Keccak_HashInstance *)hash->hash_specific_data;
	int e;
	
	if( (e=Keccak_HashFinal(instance, result)) )
	{
		fprintf(stderr,"%s: %d, %s: can't run Keccak_HashFinal! Error=%d\n",__FILE__,__LINE__,__func__,e);
		exit(1);
	}

	return 1;
}


void   keccak_ref_hash_deinit  (struct hash_iface * hash)
{
	if( hash->hash_specific_data )
	{
		free(hash->hash_specific_data);
		hash->hash_specific_data = NULL;
	}
}





