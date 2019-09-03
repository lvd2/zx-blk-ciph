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


a_dsp0	equ	2
a_dsp1	equ	1
a_dsp2	equ	5
a_dsp3	equ	4

pos_o_b0	equ	a_o_blk0+a_dsp0
pos_o_b1	equ	a_o_blk3+a_dsp1
pos_o_b2	equ	a_o_blk2+a_dsp2
pos_o_b3	equ	a_o_blk1+a_dsp3
pos_o_b4	equ	a_o_blk1+a_dsp0
pos_o_b5	equ	a_o_blk0+a_dsp1
pos_o_b6	equ	a_o_blk3+a_dsp2
pos_o_b7	equ	a_o_blk2+a_dsp3
pos_o_b8	equ	a_o_blk2+a_dsp0
pos_o_b9	equ	a_o_blk1+a_dsp1
pos_o_bA	equ	a_o_blk0+a_dsp2
pos_o_bB	equ	a_o_blk3+a_dsp3
pos_o_bC	equ	a_o_blk3+a_dsp0
pos_o_bD	equ	a_o_blk2+a_dsp1
pos_o_bE	equ	a_o_blk1+a_dsp2
pos_o_bF	equ	a_o_blk0+a_dsp3

pos_e_b0	equ	a_e_blk0+a_dsp0
pos_e_b1	equ	a_e_blk3+a_dsp1
pos_e_b2	equ	a_e_blk2+a_dsp2
pos_e_b3	equ	a_e_blk1+a_dsp3
pos_e_b4	equ	a_e_blk1+a_dsp0
pos_e_b5	equ	a_e_blk0+a_dsp1
pos_e_b6	equ	a_e_blk3+a_dsp2
pos_e_b7	equ	a_e_blk2+a_dsp3
pos_e_b8	equ	a_e_blk2+a_dsp0
pos_e_b9	equ	a_e_blk1+a_dsp1
pos_e_bA	equ	a_e_blk0+a_dsp2
pos_e_bB	equ	a_e_blk3+a_dsp3
pos_e_bC	equ	a_e_blk3+a_dsp0
pos_e_bD	equ	a_e_blk2+a_dsp1
pos_e_bE	equ	a_e_blk1+a_dsp2
pos_e_bF	equ	a_e_blk0+a_dsp3



	macro	aes_enc_ini, addr

		ld	a,[de]
		xor	[hl]
		ld	[addr],a
		inc	l
		inc	de
	endm


	macro	aes_enc_column, put0, put1, put2, put3

		;preload
		ld	bc,#0101
		ld	de,#1111

		;0th byte
		ld	l,d
		ld	a,[hl] ;sbox
		ld	l,e
		xor	[hl] ;sbox
		ld	l,b
		inc	h
		xor	[hl] ;box02
		ld	l,c
		inc	h
		xor	[hl] ;box03

		exx
		xor	[hl]
		inc	l
		ld	[put0],a
		exx

		;1st byte
		ld	l,d
		ld	a,[hl] ;box03
		ld	l,c
		dec	h
		xor	[hl] ;box02
		ld	l,b
		dec	h
		xor	[hl] ;sbox
		ld	l,e
		xor	[hl] ;sbox

		exx
		xor	[hl]
		inc	l
		ld	[put1],a
		exx

		;2nd byte
		ld	l,b
		ld	a,[hl] ;sbox
		ld	l,c
		xor	[hl] ;sbox
		ld	l,d
		inc	h
		xor	[hl] ;box02
		ld	l,e
		inc	h
		xor	[hl] ;box03

		exx
		xor	[hl]
		inc	l
		ld	[put2],a
		exx

		;3rd byte
		ld	l,b
		ld	a,[hl] ;box03
		ld	l,e
		dec	h
		xor	[hl] ;box02
		ld	l,c
		dec	h
		xor	[hl] ;sbox
		ld	l,d
		xor	[hl] ;sbox

		exx
		xor	[hl]
		inc	l
		ld	[put3],a
		exx

	endm



	macro	aes_enc_fin, src

		ld	a,[src]
		ld	e,a
		ld	a,[de]
		xor	[hl]
		ld	[bc],a
		inc	l
		inc	bc

	endm



	macro	aes_dbg, src
		ld	a,[src]
		ld	[hl],a
		inc	hl
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






aes_encrypt:
		;HL - from
		;DE - to
		push	de

		exd
		ld	hl,keys

		aes_enc_ini	pos_o_b0
		aes_enc_ini	pos_o_b1
		aes_enc_ini	pos_o_b2
		aes_enc_ini	pos_o_b3
		aes_enc_ini	pos_o_b4
		aes_enc_ini	pos_o_b5
		aes_enc_ini	pos_o_b6
		aes_enc_ini	pos_o_b7
		aes_enc_ini	pos_o_b8
		aes_enc_ini	pos_o_b9
		aes_enc_ini	pos_o_bA
		aes_enc_ini	pos_o_bB
		aes_enc_ini	pos_o_bC
		aes_enc_ini	pos_o_bD
		aes_enc_ini	pos_o_bE
		aes_enc_ini	pos_o_bF
		org	$-1




		exx
		ld	h,sbox/256
		ld	ixl,5
		jp	aes_encrypt_middle

aes_encrypt_loop

		exx
a_e_blk0	aes_enc_column	pos_o_b0, pos_o_b1, pos_o_b2, pos_o_b3
a_e_blk1	aes_enc_column	pos_o_b4, pos_o_b5, pos_o_b6, pos_o_b7
a_e_blk2	aes_enc_column	pos_o_b8, pos_o_b9, pos_o_bA, pos_o_bB
a_e_blk3	aes_enc_column	pos_o_bC, pos_o_bD, pos_o_bE, pos_o_bF

aes_encrypt_middle

a_o_blk0	aes_enc_column	pos_e_b0, pos_e_b1, pos_e_b2, pos_e_b3
a_o_blk1	aes_enc_column	pos_e_b4, pos_e_b5, pos_e_b6, pos_e_b7
a_o_blk2	aes_enc_column	pos_e_b8, pos_e_b9, pos_e_bA, pos_e_bB
a_o_blk3	aes_enc_column	pos_e_bC, pos_e_bD, pos_e_bE, pos_e_bF
		org	$-1
	
		dec	ixl
		jp	nz,aes_encrypt_loop

		pop	bc
		ld	d,sbox/256

		aes_enc_fin	a_e_blk0+a_dsp0
		aes_enc_fin	a_e_blk0+a_dsp1
		aes_enc_fin	a_e_blk0+a_dsp2
		aes_enc_fin	a_e_blk0+a_dsp3
		;
		aes_enc_fin	a_e_blk1+a_dsp0
		aes_enc_fin	a_e_blk1+a_dsp1
		aes_enc_fin	a_e_blk1+a_dsp2
		aes_enc_fin	a_e_blk1+a_dsp3
		;
		aes_enc_fin	a_e_blk2+a_dsp0
		aes_enc_fin	a_e_blk2+a_dsp1
		aes_enc_fin	a_e_blk2+a_dsp2
		aes_enc_fin	a_e_blk2+a_dsp3
		;
		aes_enc_fin	a_e_blk3+a_dsp0
		aes_enc_fin	a_e_blk3+a_dsp1
		aes_enc_fin	a_e_blk3+a_dsp2
		aes_enc_fin	a_e_blk3+a_dsp3
		org	$-2

		ret

