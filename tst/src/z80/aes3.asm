; Z80 ciphers test framework
; (c) 2019 lvd^mhm

;    This file is part of Z80 ciphers test framework.
;
;    Z80 ciphers test framework is free software:
;    you can redistribute it and/or modify it under the terms of
;    the GNU General Public License as published by
;    the Free Software Foundation, either version 3 of the License, or
;    (at your option) any later version.
;
;    Z80 ciphers test framework is distributed in the hope that
;    it will be useful, but WITHOUT ANY WARRANTY; without even
;    the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
;    See the GNU General Public License for more details.
;
;    You should have received a copy of the GNU General Public License
;    along with Z80 ciphers test framework.
;    If not, see <http://www.gnu.org/licenses/>.

st_00		equ	 0
st_01		equ	 5
st_02		equ	10
st_03		equ	15

st_10		equ	 4
st_11		equ	 9
st_12		equ	14
st_13		equ	 3

st_20		equ	 8
st_21		equ	13
st_22		equ	 2
st_23		equ	 7

st_30		equ	12
st_31		equ	 1
st_32		equ	 6
st_33		equ	11


	macro	aes_column,disp0,disp1,disp2,disp3


if st_00=disp0
	macro 	xor0
	xor 	(ix+0)
	endm
	macro 	ld0
	ld 	(__st_00+1),a
	endm
_st_10	ld	l,0	; +0   C
else
if st_10=disp0
	macro 	xor0
	xor 	(ix+4)
	endm
	macro 	ld0
	ld 	(__st_04+1),a
	endm
_st_14	ld	l,0
else
if st_20=disp0
	macro 	xor0
	xor 	(ix+8)
	endm
	macro 	ld0
	ld 	(__st_08+1),a
	endm
_st_02	ld	l,0
else
if st_30=disp0
	macro 	xor0
	xor 	(ix+12)
	endm
	macro 	ld0
	ld 	(__st_12+1),a
	endm
_st_06	ld	l,0
else
if (st_00+16)=disp0
	macro 	xor0
	xor 	(ix+16)
	endm
	macro 	ld0
	ld 	(_st_00+1),a
	endm
_st__10	ld	l,0
else
if (st_10+16)=disp0
	macro 	xor0
	xor 	(ix+20)
	endm
	macro 	ld0
	ld 	(_st_04+1),a
	endm
_st__14	ld	l,0
else
if (st_20+16)=disp0
	macro 	xor0
	xor 	(ix+24)
	endm
	macro 	ld0
	ld 	(_st_08+1),a
	endm
_st__02	ld	l,0
else
;;if st_30=disp0
	macro 	xor0
	xor 	(ix+28)
	endm
	macro 	ld0
	ld 	(_st_12+1),a
	endm
_st__06	ld	l,0
endif
endif
endif
endif
endif
endif
endif
	ld	e,(hl)
	inc	h
	ld	d,(hl)
	ld	a,e

if st_00=disp0
	macro 	xor1
	xor 	(ix+1)
	endm
	macro 	ld1
	ld 	(__st_01+1),a
	endm
_st_15	ld	l,0	; +0   C
else
if st_10=disp0
	macro 	xor1
	xor 	(ix+5)
	endm
	macro 	ld1
	ld 	(__st_05+1),a
	endm
_st_03	ld	l,0
else
if st_20=disp0
	macro 	xor1
	xor 	(ix+9)
	endm
	macro 	ld1
	ld 	(__st_09+1),a
	endm
_st_07	ld	l,0
else
if st_30=disp0
	macro 	xor1
	xor 	(ix+13)
	endm
	macro 	ld1
	ld 	(__st_13+1),a
	endm
_st_11	ld	l,0
else
if (st_00+16)=disp0
	macro 	xor1
	xor 	(ix+17)
	endm
	macro 	ld1
	ld 	(_st_01+1),a
	endm
_st__15	ld	l,0
else
if (st_10+16)=disp0
	macro 	xor1
	xor 	(ix+21)
	endm
	macro 	ld1
	ld 	(_st_05+1),a
	endm
_st__03	ld	l,0
else
if (st_20+16)=disp0
	macro 	xor1
	xor 	(ix+25)
	endm
	macro 	ld1
	ld 	(_st_09+1),a
	endm
_st__07	ld	l,0
else
;;if st_30=disp0
	macro 	xor1
	xor 	(ix+29)
	endm
	macro 	ld1
	ld 	(_st_13+1),a
	endm
_st__11	ld	l,0
endif
endif
endif
endif
endif
endif
endif
	ld	b,(hl)
	dec	h
	ld	c,(hl)
	xor	c
	exx

if st_00=disp0
	macro 	xor2
	xor 	(ix+2)
	endm
	macro 	ld2
	ld 	(__st_02+1),a
	endm
_st_00	ld	l,0	; +0   C
else
if st_10=disp0
	macro 	xor2
	xor 	(ix+6)
	endm
	macro 	ld2
	ld 	(__st_06+1),a
	endm
_st_04	ld	l,0
else
if st_20=disp0
	macro 	xor2
	xor 	(ix+10)
	endm
	macro 	ld2
	ld 	(__st_10+1),a
	endm
_st_08	ld	l,0
else
if st_30=disp0
	macro 	xor2
	xor 	(ix+14)
	endm
	macro 	ld2
	ld 	(__st_14+1),a
	endm
_st_12	ld	l,0
else
if (st_00+16)=disp0
	macro 	xor2
	xor 	(ix+18)
	endm
	macro 	ld2
	ld 	(_st_02+1),a
	endm
_st__00	ld	l,0
else
if (st_10+16)=disp0
	macro 	xor2
	xor 	(ix+22)
	endm
	macro 	ld2
	ld 	(_st_06+1),a
	endm
_st__04	ld	l,0
else
if (st_20+16)=disp0
	macro 	xor2
	xor 	(ix+26)
	endm
	macro 	ld2
	ld 	(_st_10+1),a
	endm
_st__08	ld	l,0
else
;;if st_30=disp0
	macro 	xor2
	xor 	(ix+30)
	endm
	macro 	ld2
	ld 	(_st_14+1),a
	endm
_st__12	ld	l,0
endif
endif
endif
endif
endif
endif
endif
	ld	c,(hl)
	inc	h
	ld	b,(hl)
	xor	b

if st_00=disp0
	macro 	xor3
	xor 	(ix+3)
	endm
	macro 	ld3
	ld 	(__st_03+1),a
	endm
_st_05	ld	l,0	; +0   C
else
if st_10=disp0
	macro 	xor3
	xor 	(ix+7)
	endm
	macro 	ld3
	ld 	(__st_07+1),a
	endm
_st_09	ld	l,0
else
if st_20=disp0
	macro 	xor3
	xor 	(ix+11)
	endm
	macro 	ld3
	ld 	(__st_11+1),a
	endm
_st_13	ld	l,0
else
if st_30=disp0
	macro 	xor3
	xor 	(ix+15)
	endm
	macro 	ld3
	ld 	(__st_15+1),a
	endm
_st_01	ld	l,0
else
if (st_00+16)=disp0
	macro 	xor3
	xor 	(ix+19)
	endm
	macro 	ld3
	ld 	(_st_03+1),a
	endm
_st__05	ld	l,0
else
if (st_10+16)=disp0
	macro 	xor3
	xor 	(ix+23)
	endm
	macro 	ld3
	ld 	(_st_07+1),a
	endm
_st__09	ld	l,0
else
if (st_20+16)=disp0
	macro 	xor3
	xor 	(ix+27)
	endm
	macro 	ld3
	ld 	(_st_11+1),a
	endm
_st__13	ld	l,0
else
;;if st_30=disp0
	macro 	xor3
	xor 	(ix+31)
	endm
	macro 	ld3
	ld 	(_st_15+1),a
	endm
_st__01	ld	l,0
endif
endif
endif
endif
endif
endif
endif
	ld	d,(hl)
	dec	h
	ld	e,(hl)
	xor	e
	xor	d
	xor0	;;xor	(ix+index+0)
	ld0	;;	(sv00+1),a
	
	ld	a,c 	; sbox00 B
	xor	d 	; sbox02 D
	
	exx
	xor	e	; sbox   C
	xor	c	; sbox03 E
	xor	b
	xor1	;;xor	(ix+index+1)
	ld1	;;	(sv01+1),a

	ld	a,b 	; sbox02 E
	xor	e	; sbox03 C
	xor	d
	exx
	xor	c	; sbox   B
	xor	d	; sbox   D
	xor2	;;xor	(ix+index+2)
	ld2	;;(sv02+1),a

	ld	a,e
	xor	c
	xor	b
	exx
	xor	c	; sbox   E
	xor	e	; sbox02 C 
	xor3	;;(ix+index+3)
	ld3	;;(sv03+1),a

		endm







aes_init:	;init some tables


		;init sbox
		ld	hl,sbox
		ld	bc,#1A09
		ld	de,#6301
		ld	[hl],d
aes_sbox_loop1
		inc	l
		ld	a,l
		rlca
		jr	nc,$+3
		xor	b ;#1A
		xor	l
		ld	l,a

		ld	a,e
		add	a,a
		xor	e
		ld	e,a

		add	a,a
		add	a,a
		xor	e
		ld	e,a

		add	a,a
		add	a,a
		add	a,a
		add	a,a
		xor	e
		jp	p,$+4
		xor	c ;#09
		ld	e,a		

		rlca
		xor	e
		rlca
		xor	e
		rlca
		xor	e
		rlca
		xor	e

		xor	d ;#63

		ld	[hl],a

		dec	l
		jr	nz,aes_sbox_loop1


		;make tables for sbox[i]*{02} and sbox[i]*{03}
		ld	d,box02/256
		ld	b,box03/256
aes_sbox_loop2
		ld	e,l
		ld	c,l

		ld	a,[hl]
		rlca
		jr	nc,$+4
		xor	#1A
		ld	[de],a
		xor	[hl]
		ld	[bc],a

		inc	l
		jr	nz,aes_sbox_loop2

		ret




aes_setkey:	;HL - ptr to key (16 bytes)

		ld	de,keys

		 rept	 15
		ldi
		 endm
		ld	a,[hl]
		ld	[de],a


		ld	ixl,10
		ld	hl,aes_rcons
		exx

		ld	hl,keys+16-4 ; last word of initial block
setkey_loop:
		; make SubWord, RotWord and xor Rcon -- into registers
		ld	d,sbox/256

		ld	e,[hl]
		ld	a,[de]
		exa
		inc	l

		ld	e,[hl]
		ld	a,[de]
		 exx
		 xor	[hl]
		 inc	 hl
		 exx
		ld	b,a
		inc	l

		ld	e,[hl]
		ld	a,[de]
		ld	c,a
		inc	l

		ld	e,[hl]
		ld	a,[de]
		inc	l

	
		;make 1st word of next subkey (or block)
		ld	[hl],b
		inc	l
		ld	[hl],c
		inc	l
		ld	[hl],a
		inc	l
		exa
		ld	[hl],a	;put processed word first

		ld	d,h
		ld	a,l
		sub	16
		ld	e,a ;then xor processed word from same word of previous block

		 rept	 4
		ld	a,[de]
		xor	[hl]
		ld	[hl],a
		dec	e
		dec	l
		 endm
		org	$-2

		;prepare to make remaining 3 words of the subkey
		ld	a,l
		add	a,4
		ld	e,a ;de=destination (2nd word)

		ld	b,h
		sub	16
		ld	c,a ;bc = same word from previous block
			    ;hl = previous word from current block

		 rept	 12
		ld	a,[bc]
		xor	[hl]
		ld	[de],a
		inc	l
		inc	c
		inc	e
		 endm
		org	$-2
	
		;hl = this block's last word, will be used in next iteration

		dec	ixl
		jp	nz,setkey_loop
		ret

aes_rcons:	db	#01,#02,#04,#08,#10,#20,#40,#80,#1B,#36










		macro	first_subkey,st
		ld	a,(de)
		xor	(hl)
		ld 	(st+1),a
		inc	e
		inc	hl
		endm


		macro	aes_final,disp

		ld	a,(disp+1)
		ld	l,a
		ld	a,(de)
		xor	(hl)
		ld	(bc),a
		inc	e
		inc	bc

		endm



aes_encrypt:
		;HL - from
		;DE - to
		push	de

		ld	de,keys

		;add first subkey
		first_subkey	_st_00
		first_subkey	_st_01
		first_subkey	_st_02
		first_subkey	_st_03
		first_subkey	_st_04
		first_subkey	_st_05
		first_subkey	_st_06
		first_subkey	_st_07
		first_subkey	_st_08
		first_subkey	_st_09
		first_subkey	_st_10
		first_subkey	_st_11
		first_subkey	_st_12
		first_subkey	_st_13
		first_subkey	_st_14
		first_subkey	_st_15
		org	$-1

		ld  	ixl,e
		ld  	ixh,d

		ld	h,sbox/256
		exx
		ld	h,sbox/256
		exx

		;ld	ixl,5
		;ld	de,state+16

		ld 	a,5
		exa
		jp	aes_encrypt_middle

aes_encrypt_loop:
		exa
		;state2->state1 round

		aes_column	16+st_00,16+st_01,16+st_02,16+st_03
		aes_column	16+st_10,16+st_11,16+st_12,16+st_13
		aes_column	16+st_20,16+st_21,16+st_22,16+st_23
		aes_column	16+st_30,16+st_31,16+st_32,16+st_33
		ld 	de,32
		add 	ix,de
aes_encrypt_middle:
		;state1->state2 round


		aes_column	00+st_00,00+st_01,00+st_02,00+st_03
		aes_column	00+st_10,00+st_11,00+st_12,00+st_13
		aes_column	00+st_20,00+st_21,00+st_22,00+st_23
		aes_column	00+st_30,00+st_31,00+st_32,00+st_33

		exa		
		dec	a
		jp	nz,aes_encrypt_loop

		ld 	de,16
		add 	ix,de
		ld  	e,ixl
		ld  	d,ixh

		;final round (SubBytes, ShiftRows, AddRoundKey), state2->output
		;hl'=keys
		;exd

		pop	bc

		;ld	h,sbox/256
		;de=keys, bc=dst,hl=sbox

		aes_final		_st__00
		aes_final		_st__01
		aes_final		_st__02
		aes_final		_st__03
		aes_final		_st__04
		aes_final		_st__05
		aes_final		_st__06
		aes_final		_st__07
		aes_final		_st__08
		aes_final		_st__09
		aes_final		_st__10
		aes_final		_st__11
		aes_final		_st__12
		aes_final		_st__13
		aes_final		_st__14
		aes_final		_st__15
		org	$-2
		ret
