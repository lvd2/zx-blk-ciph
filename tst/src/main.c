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
#include <strings.h>

#include "libz80/z80.h"
#include "ciph-common.h"
#include "hash-common.h"

#ifdef GCRYPT
 #include "gcrypt-aes128.h"
 #include "gcrypt-bf.h"
#endif

#include "my-c-aes128.h"
#include "my-t-aes128.h"
#include "my-z80-aes128.h"

#include "my-c-bf.h"
#include "my-z80-bf.h"

#include "my-c-speck.h"
#include "my-z80-speck.h"

#include "keccak-ref.h"
#include "keccak-my.h"
#include "keccak-nagy-z80.h"

#include "tests-cipher.h"
#include "tests-hash.h"
#include "run-test.h"




struct hash_run
{
	struct hash_iface * (*make_function)(void);
	const struct tests_hash * tests;
	const char * what;
};




int main(int argc, char ** argv)
{
	int t_aes=0;
	int t_bf=0;
	int t_speck=0;
	int t_keccak=0;

	int t_z80=0;

	int t_long_keccak=0;




#ifdef GCRYPT
	run_tests_cipher(bf_tests,     &make_gcrypt_bf    );
	run_tests_cipher(aes128_tests, &make_gcrypt_aes128);
	printf("gcrypt tests done!\n");
#endif

	run_tests_cipher(bf_tests,     &make_my_c_bf    );
	run_tests_cipher(aes128_tests, &make_my_c_aes128);
	run_tests_cipher(aes128_tests, &make_my_t_aes128);
	run_tests_cipher(speck_tests,  &make_my_c_speck );

	run_tests_hash(keccak_256, &make_keccak_ref);
	run_tests_hash(keccak_256, &make_keccak_my );





	// parse arguments
	if( argc>=2 )
	{
		int i=1;

		do
		{
			char * arg=argv[i];

			     if( !strcasecmp(arg,"aes"       ) )
				t_aes=1;
			else if( !strcasecmp(arg,"bf"        ) )
				t_bf=1;
			else if( !strcasecmp(arg,"speck"     ) )
				t_speck=1;
			else if( !strcasecmp(arg,"z80"       ) )
				t_z80=1;
			else if( !strcasecmp(arg,"longkeccak") )
				t_long_keccak=1;
			else if( !strcasecmp(arg,"keccak"    ) )
				t_keccak=1;
			else
			{
				printf("arguments: 'aes, 'bf' or 'speck' -- run specific Z80 tests,\n"
				       "           'keccak'              -- run Nagy's Z80 keccak test,\n"
				       "           'z80'                 -- run all fast Z80 tests,\n"
				       "           'longkeccak'          -- run all long keccak tests\n"
				       "           no arguments          -- run only fast non-Z80 tests\n");
				exit(1);
			}

		} while( (++i)<argc );
	}







	// long keccak tests
	if( t_long_keccak )
	{
		static struct hash_run hash[] =
		{
			{ &make_keccak_ref, long_keccak_256, "LOONG reference keccak" },
			{ &make_keccak_my,  long_keccak_256, "LOONG my keccak" },
			{ NULL, NULL, NULL }
		};

		struct hash_run * curr = hash;

		while( curr->make_function )
		{
			printf("Running %s\n",curr->what);
			run_tests_hash(curr->tests, curr->make_function);
			curr++;
		}

		if( t_keccak )
		{
			printf("Running LOONG Nagy's Z80 keccak\n");
			run_tests_hash(long_keccak_256, &make_keccak_nagy_z80);
		}
	}
	

	// z80-related tests
	if( t_aes || t_z80 )
	{
		run_tests_cipher(aes128_tests, &make_my_z80_aes128);
	}
	
	if( t_bf || t_z80 )
	{
		run_tests_cipher(bf_tests,     &make_my_z80_bf);
	}
	
	if( t_speck || t_z80 )
	{
		run_tests_cipher(speck_tests,  &make_my_z80_speck);
	}

	if( t_keccak || t_z80 )
	{
		run_tests_hash(keccak_256, &make_keccak_nagy_z80);
	}



	printf("Tests passed!\n");

	return 0;
}

