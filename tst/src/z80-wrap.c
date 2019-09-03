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




static uint8_t z80_rd(void * param, uint16_t address)
{
	if( !param )
	{
		fprintf(stderr,"%s: %d, %s: z80 tries to read the ports!\n",__FILE__,__LINE__,__FUNCTION__);
		exit(1);
	}

	struct z80_context * z80 = param;

	return z80->z80_mem[address];
}

static void    z80_wr(void * param, uint16_t address, uint8_t data)
{
	if( !param )
	{
		fprintf(stderr,"%s: %d, %s: z80 tries to write the ports!\n",__FILE__,__LINE__,__FUNCTION__);
		exit(1);
	}

	struct z80_context * z80 = param;

	z80->z80_mem[address] = data;
}





struct z80_context * z80_init(char * filename)
{
	// allocate structure for z80 context and associated data
	//



	struct z80_context * z80 = malloc(sizeof(struct z80_context));
	//
	if( !z80 )
	{
		fprintf(stderr,"%s: %d, %s: can't allocate memory for struct z80_context!\n",__FILE__,__LINE__,__func__);
		exit(1);
	}

	// clear Z80 memory
	memset(z80->z80_mem,0,65536);


	// load Z80 binary, if needed
	if( filename )
	{
		FILE * f = fopen(filename,"rb");
		if( !f )
		{
			fprintf(stderr,"%s: %d, %s: can't open Z80 binary file <%s>!\n",__FILE__,__LINE__,__FUNCTION__,filename);
			exit(1);
		}
		//
		size_t read=fread(z80->z80_mem,1,65536,f);
		off_t o=ftello(f);
		int seek=fseeko(f,0,SEEK_END);
		off_t e=ftello(f);
		if( seek || o!=e || read!=e || !(0<o && o<=65536) )
		{
			fprintf(stderr,"%s: %d, %s: can't read Z80 binary file <%s>!\n",__FILE__,__LINE__,__FUNCTION__,filename);
			exit(1);
		}
		fclose(f);
	}

	// initialize Z80 stuff
	z80->z80.memParam = z80;
	z80->z80.ioParam  = NULL;
	//
	z80->z80.memRead = z80_rd;
	z80->z80.ioRead  = z80_rd;
	z80->z80.memWrite = z80_wr;
	z80->z80.ioWrite  = z80_wr;


	Z80RESET(&(z80->z80));


	return z80;
}




unsigned z80_execute(struct z80_context * z80, unsigned max_clocks, uint16_t addr)
{
	Z80RESET(&(z80->z80));

	z80->z80.PC = addr;
	
	unsigned clocks = Z80ExecuteTStates(&(z80->z80), max_clocks);


	if( !z80->z80.halted )
		return 0;
	
	return clocks;
}





uint8_t  z80_rdbyte(struct z80_context * z80, uint16_t addr)
{
	return z80->z80_mem[addr];
}

uint16_t z80_rdword_le(struct z80_context * z80, uint16_t addr)
{
	return (((uint16_t)z80_rdbyte(z80,addr+0)) & 0x00FF) |
	       (((uint16_t)z80_rdbyte(z80,addr+1)) << 8    ) ;
}

uint32_t z80_rdlong_le(struct z80_context * z80, uint16_t addr)
{
	return (((uint32_t)z80_rdword_le(z80,addr+0)) & 0x0000FFFF) |
	       (((uint32_t)z80_rdword_le(z80,addr+2)) << 16       ) ;
}

uint64_t z80_rdocta_le(struct z80_context * z80, uint16_t addr)
{
	return (((uint64_t)z80_rdlong_le(z80,addr+0)) & 0xFFFFFFFFull) |
	       (((uint64_t)z80_rdlong_le(z80,addr+4)) << 32          ) ;
}

void z80_wrbyte(struct z80_context * z80, uint16_t addr, uint8_t  data)
{
	z80->z80_mem[addr]=data;
}

void z80_wrword_le(struct z80_context * z80, uint16_t addr, uint16_t data)
{
	z80_wrbyte(z80,addr+0,data & 0x00FF);
	z80_wrbyte(z80,addr+1,data >> 8    );
}

void z80_wrlong_le(struct z80_context * z80, uint16_t addr, uint32_t data)
{
	z80_wrword_le(z80,addr+0,data & 0x0000FFFF);
	z80_wrword_le(z80,addr+2,data >> 16       );
}

void z80_wrocta_le(struct z80_context * z80, uint16_t addr, uint64_t data)
{
	z80_wrlong_le(z80,addr+0,data & 0xFFFFFFFFull);
	z80_wrlong_le(z80,addr+4,data >> 32          );
}

