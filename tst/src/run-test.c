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

#include "tests-cipher.h"
#include "ciph-common.h"
#include "run-test.h"

static uint8_t * hex2bin (const char * hex);
static size_t    hex2size(const char * hex);
static uint8_t   hex_digit(char digit);



int run_tests_cipher(const struct tests_cipher tests[], struct ciph_iface *(*mk_ciph)())
{
	struct ciph_iface * ciph = (*mk_ciph)();

	(*ciph->ciph_init)(ciph);


	uint8_t * key;
	size_t    key_size;

	uint8_t * plain;
	size_t    plain_size;

	uint8_t * cipher;
	size_t    cipher_size;

	uint8_t * src;
	uint8_t * dst;
	uint8_t * tmp;

	size_t size;

	const struct tests_cipher * test = tests;

	while( test->hex_key && test->hex_plain && test->hex_cipher )
	{
		key_size = hex2size( test->hex_key );
		key      = hex2bin ( test->hex_key );

		plain_size = hex2size( test->hex_plain );
		plain      = hex2bin ( test->hex_plain );

		cipher_size = hex2size( test->hex_cipher );
		cipher      = hex2bin ( test->hex_cipher );

		if( !test->iterations )
		{
			fprintf(stderr,"%s: %d, %s: ZERO iterations!\n",__FILE__,__LINE__,__func__);
			exit(1);
		}

		if( plain_size != cipher_size )
		{
			fprintf(stderr,"%s: %d, %s: plaintext and ciphertext are of different sizes!\n",__FILE__,__LINE__,__func__);
			exit(1);
		}

		size = plain_size;
//printf("key size=%ld, block size=%ld\n",key_size,size);
	
		// allocate temporary storage
		src = malloc(size);
		dst = malloc(size);
		if( !src || !dst )
		{
			fprintf(stderr,"%s: %d, %s: can't allocate storage for temporary space!\n",__FILE__,__LINE__,__func__);
			exit(1);
		}

		// setup key
		(*ciph->ciph_setkey)(ciph,key,key_size);

		// copy plaintext
		memset(dst,0,size);
		memcpy(src,plain,size);

		// encrypt iterations
		for(unsigned int i=0;i<test->iterations;i++)
		{
			(*ciph->ciph_enc)(ciph,src,dst,size);

			tmp=src;src=dst;dst=tmp;
		}

		// check encryption
		if( memcmp(src,cipher,size) )
		{
			fprintf(stderr,"%s: %d, %s: encryption failed!\n",__FILE__,__LINE__,__func__);
			fprintf(stderr,"note: name=\"%s\"\n",ciph->name);
			fprintf(stderr,"note: vector=(key=%s, plain=%s, cipher=%s, iterations=%u)\n",test->hex_key,test->hex_plain,test->hex_cipher,test->iterations);
			fprintf(stderr,"note: actual key:        %016lx\n",__builtin_bswap64(*(uint64_t *)key));
			fprintf(stderr,"note: actual plaintext:  %016lx\n",__builtin_bswap64(*(uint64_t *)plain));
			fprintf(stderr,"note: actual ciphertext: %016lx\n",__builtin_bswap64(*(uint64_t *)src));
			exit(1);
		}


		
		// copy ciphertext
		memset(dst,0,size);
		memcpy(src,cipher,size);

		// decrypt iterations
		for(unsigned int i=0;i<test->iterations;i++)
		{
			(*ciph->ciph_dec)(ciph,src,dst,size);

			tmp=src;src=dst;dst=tmp;
		}

		// check decryption
		if( memcmp(src,plain,size) )
		{
			fprintf(stderr,"%s: %d, %s: decryption failed!\n",__FILE__,__LINE__,__func__);
			fprintf(stderr,"note: name=\"%s\"\n",ciph->name);
			fprintf(stderr,"note: vector=(key=%s, plain=%s, cipher=%s, iterations=%u)\n",test->hex_key,test->hex_plain,test->hex_cipher,test->iterations);
			fprintf(stderr,"note: actual key:        %016lx\n",__builtin_bswap64(*(uint64_t *)key));
			fprintf(stderr,"note: actual ciphertext: %016lx\n",__builtin_bswap64(*(uint64_t *)cipher));
			fprintf(stderr,"note: actual plaintext:  %016lx\n",__builtin_bswap64(*(uint64_t *)src));
			exit(1);
		}

		free(src);free(dst);
		free(cipher);free(plain);free(key);

		test++;
	}


	(*ciph->ciph_deinit)(ciph);	
}




static uint8_t * hex2bin (const char * hex)
{
	size_t len = hex2size(hex);

	uint8_t * bin = malloc(len);

	if( !bin )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate binary for hex string!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	uint8_t * curr_bin = bin;
	const char * curr_hex = hex;

	while( *curr_hex )
	{
		uint8_t val,byte;

		while( (val=hex_digit(*(curr_hex++)))==255 );
		byte = val<<4;
		while( (val=hex_digit(*(curr_hex++)))==255 );
		byte |= (val&15);

		*(curr_bin++) = byte;
	}

	return bin;
}

static size_t    hex2size(const char * hex)
{
	size_t tot_len = strlen(hex);
	size_t hex_len = 0;

	for(size_t i=0;i<tot_len;i++)
	{
		hex_len += (hex_digit(hex[i])!=255);
	}

	if( hex_len%2 != 0 )
	{
		fprintf(stderr,"%s: %d, %s: odd number of hex digits!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	return hex_len/2;
}

static uint8_t   hex_digit(char digit)
{
	switch(digit)
	{
		case '0'...'9': return digit-'0';    break;
		case 'A'...'F': return digit-'A'+10; break;
		case 'a'...'f': return digit-'a'+10; break;
//		default:
//			fprintf(stderr,"%s: %d, %s: non-hex digit!\n",__FILE__,__LINE__,__func__);
//			exit(1);
//			break;
	}

	return 255;
}

