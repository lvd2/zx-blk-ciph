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

#include "hash-common.h"
#include "keccak-nagy-z80.h"



#define KETYPE uint64_t
#define KEBITS (64)
#define KEMASK (0xFFFFFFFFFFFFFFFFull)

#include "keccak.inc"




struct hash_iface * make_keccak_nagy_z80(void)
{
	static const char name[]="Daniel Nagy's Z80 keccak";

	struct hash_iface * hash = malloc(sizeof(struct hash_iface));
	if( !hash )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for hash_iface!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	hash->hash_specific_data = NULL;

	hash->name = name;

	hash->hash_init     = &keccak_nagy_z80_hash_init;
	hash->hash_start    = &keccak_nagy_z80_hash_start;
	hash->hash_addbytes = &keccak_nagy_z80_hash_addbytes;
	hash->hash_getsize  = &keccak_nagy_z80_hash_getsize;
	hash->hash_result   = &keccak_nagy_z80_hash_result;
	hash->hash_deinit   = &keccak_nagy_z80_hash_deinit;

	return hash;
}


int    keccak_nagy_z80_hash_init    (struct hash_iface * hash)
{
	struct nagy_z80_keccak * keccak = malloc(sizeof(struct nagy_z80_keccak));
	
	struct z80_context * z80;
	
	
	if( !keccak )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for nagy_z80_keccak!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	hash->hash_specific_data = (void *)keccak;


	// load Z80 binary
	z80=z80_init("z80/nagy_keccak_test.bin");
	
	keccak->z80 = z80;


	return 1;
}




int    keccak_nagy_z80_hash_start   (struct hash_iface * hash)
{
	struct nagy_z80_keccak * keccak = (struct nagy_z80_keccak *)hash->hash_specific_data;

	keccak->pos = 0;
	
	for(unsigned int i=0;i<25;i++)
		keccak->state[i] = 0;


	// run Z80 clear state
	unsigned clocks = z80_execute(keccak->z80, Z80_MAX_CLOCKS, Z80_KC_INIT);
	if( !clocks )
	{
		fprintf(stderr,"%s: %d, %s: Nagy's Z80 keccak init didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
		fprintf(stderr,"pc=%04x\n",keccak->z80->z80.PC);
		exit(1);
	}
	printf("KECCAK: %d clocks to init (%s)\n",clocks,__func__);
	

	// check state clearness
	for(int i=0;i<25;i++)
	{
		uint64_t word = z80_rdocta_le(keccak->z80, Z80_KC_STATE_ADDR+i*8);
		if( word )
		{	
			fprintf(stderr,"%s: state clearness check failed: at %d, z80=%016lx\n",__func__,i,word);
			exit(1);
		}
	}


	return 1;
}



int    keccak_nagy_z80_hash_addbytes(struct hash_iface * hash, uint8_t * message, size_t size)
{
	struct nagy_z80_keccak * keccak = (struct nagy_z80_keccak *)hash->hash_specific_data;

	size_t curr_size;

	uint8_t * state = (uint8_t *)keccak->state;


	while( size>0 )
	{
		curr_size = MY_KECCAK_RATE - keccak->pos;
		if( curr_size>size ) curr_size = size;


		for(unsigned int i=0;i<curr_size;i++)
		{
			state[keccak->pos++] ^= *message;



			// add byte to Z80 keccak
			z80_wrbyte(keccak->z80, Z80_KC_BYTE_ADDR, *message);
			//
			unsigned clocks = z80_execute(keccak->z80, Z80_MAX_CLOCKS, Z80_KC_ADDBYTE);
			if( !clocks )
			{
				fprintf(stderr,"%s: %d, %s: Nagy's Z80 keccak addbyte didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
				fprintf(stderr,"pc=%04x\n",keccak->z80->z80.PC);
				exit(1);
			}
			printf("KECCAK: %d clocks to add a byte (%s)\n",clocks,__func__);



			message++;
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

size_t keccak_nagy_z80_hash_getsize (struct hash_iface * hash)
{
	return 32;
}



int    keccak_nagy_z80_hash_result  (struct hash_iface * hash, uint8_t * result)
{
	struct nagy_z80_keccak * keccak = (struct nagy_z80_keccak *)hash->hash_specific_data;

	uint8_t * state = (uint8_t *)keccak->state;
	

	state[keccak->pos     ] ^= 0x01;
	state[MY_KECCAK_RATE-1] ^= 0x80;

	keccak_permute_nrounds(keccak->state,24);


	// get Z80 hash
	unsigned clocks = z80_execute(keccak->z80, Z80_MAX_CLOCKS, Z80_KC_FINAL);
	if( !clocks )
	{
		fprintf(stderr,"%s: %d, %s: Nagy's Z80 keccak finalize didn't return after %d clocks!\n",__FILE__,__LINE__,__FUNCTION__,Z80_MAX_CLOCKS);
		fprintf(stderr,"pc=%04x\n",keccak->z80->z80.PC);
		exit(1);
	}
	printf("KECCAK: %d clocks to finalize (%s)\n",clocks,__func__);

	
	// compare Z80 and reference
	for(int i=0;i<25;i++)
	{
		uint64_t z80 = z80_rdocta_le(keccak->z80, Z80_KC_STATE_ADDR+i*8);
		uint64_t ref = keccak->state[i];

		if( z80!=ref )
		{
			fprintf(stderr,"%s: result check failed: at %d, z80=%016lx, ref=%016lx\n",__func__,i,z80,ref);
			for(i=0;i<25;i++)
			{
				if( !(i%5) && i ) fprintf(stderr,"\n");
				fprintf(stderr,"note: pos=%2d, z80=%016lx, ref=%016lx\n",i,z80_rdocta_le(keccak->z80, Z80_KC_STATE_ADDR+i*8),keccak->state[i]);
			}
			fprintf(stderr,"\nnote: B[0]=%016lx, B[1]=%016lx\n",z80_rdocta_le(keccak->z80, Z80_KC_B_ADDR),z80_rdocta_le(keccak->z80, Z80_KC_B_ADDR+8));

			exit(1);
		}
	}


	// copy result to output
	for(int i=0;i<32;i++)
	{
		result[i] = z80_rdbyte(keccak->z80, Z80_KC_STATE_ADDR+i);
	}


	return 1;
}




void   keccak_nagy_z80_hash_deinit  (struct hash_iface * hash)
{
	if( hash->hash_specific_data )
	{
		free(hash->hash_specific_data);
		hash->hash_specific_data = NULL;
	}
}





