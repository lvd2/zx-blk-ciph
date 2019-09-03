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
#include <string.h>
#include <gcrypt.h>

#include "ciph-common.h"
#include "gcrypt-bf.h"



struct ciph_iface * make_gcrypt_bf(void)
{
	static const char name[]="libgcrypt blowfish";

	struct ciph_iface * ciph = malloc(sizeof(struct ciph_iface));
	if( !ciph )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for ciph_iface!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	ciph->ciph_specific_data = NULL;

	ciph->name = name;

	ciph->ciph_init   = &gcrypt_bf_ciph_init;
	ciph->ciph_setkey = &gcrypt_bf_ciph_setkey;
	ciph->ciph_enc    = &gcrypt_bf_ciph_enc;
	ciph->ciph_dec    = &gcrypt_bf_ciph_dec;
	ciph->ciph_deinit = &gcrypt_bf_ciph_deinit;

	return ciph;
}



int gcrypt_bf_ciph_init(struct ciph_iface * ciph)
{ // init blowfish cipher

	gcry_cipher_hd_t handle;

	if( gcry_cipher_open( &handle, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, 0) )
	{
		fprintf(stderr,"%s: %d, %s: can't open cipher from libgcrypt!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	ciph->ciph_specific_data = (void *)handle;

	return 1;
}



int    gcrypt_bf_ciph_setkey(struct ciph_iface * ciph, uint8_t * key, size_t key_size)
{
	if( gcry_cipher_setkey( (gcry_cipher_hd_t)ciph->ciph_specific_data, key, key_size) )
	{
		fprintf(stderr,"%s: %d, %s: can't set the key!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	return 1;
}



int    gcrypt_bf_ciph_enc(struct ciph_iface * ciph, uint8_t * plain, uint8_t * cipher, size_t size)
{
	if( gcry_cipher_encrypt( (gcry_cipher_hd_t)ciph->ciph_specific_data, cipher, size, plain, size) )
	{
		fprintf(stderr,"%s: %d, %s: can't encrypt!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}
	
	return 1;
}

int    gcrypt_bf_ciph_dec(struct ciph_iface * ciph, uint8_t * cipher, uint8_t * plain, size_t size)
{
	if( gcry_cipher_decrypt( (gcry_cipher_hd_t)ciph->ciph_specific_data, plain, size, cipher, size) )
	{
		fprintf(stderr,"%s: %d, %s: can't encrypt!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	return 1;
}

void   gcrypt_bf_ciph_deinit(struct ciph_iface * ciph)
{
	gcry_cipher_close( (gcry_cipher_hd_t)ciph->ciph_specific_data );
}






