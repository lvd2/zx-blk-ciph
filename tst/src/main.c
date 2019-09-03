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

#include "tests-cipher.h"
#include "run-test.h"

int main(int argc, char ** argv)
{
#ifdef GCRYPT
	run_tests_cipher(bf_tests,     &make_gcrypt_bf    );
	run_tests_cipher(aes128_tests, &make_gcrypt_aes128);
	printf("gcrypt tests done!\n");
#endif

	run_tests_cipher(bf_tests,     &make_my_c_bf    );
	run_tests_cipher(aes128_tests, &make_my_c_aes128);
	run_tests_cipher(aes128_tests, &make_my_t_aes128);
	run_tests_cipher(speck_tests,  &make_my_c_speck );


	int t_aes=1;
	int t_bf=1;
	int t_speck=1;

	if( argc>=2 )
	{
		t_aes   =0;
		t_bf    =0;
		t_speck =0;

		     if( !strcasecmp(argv[1],"aes") )
			t_aes=1;
		else if( !strcasecmp(argv[1],"bf") )
			t_bf=1;
		else if( !strcasecmp(argv[1],"speck") )
			t_speck=1;
		else
		{
			printf("no args -- all tests, AES BF or SPECK -- specific test\n");
			exit(1);
		}
	}
	
	
	// z80-related tests
	if( t_aes )
	{
		run_tests_cipher(aes128_tests, &make_my_z80_aes128);
	}
	
	if( t_bf )
	{
		run_tests_cipher(bf_tests,     &make_my_z80_bf);
	}
	
	if( t_speck )
	{
		run_tests_cipher(speck_tests,  &make_my_z80_speck);
	}


	printf("Tests passed!\n");

	return 0;
}

