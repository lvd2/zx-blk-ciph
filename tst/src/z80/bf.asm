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


bf_setkey:	;HL - key
		;A - size of key (1..56 bytes)

		push	hl
		push	af

		;copy initial values of keys
		ld	hl,bf_ini_keys
		ld	de,bf_keys
		ld	bc,18*4
		ldir

		;copy initial values of s-boxes
		ld	de,bf_ini_s0
		ld	c,0
		;
		ld	hl,bf_setkey_s0a
		call	bf_setkey_cpys
		;
		ld	hl,bf_setkey_s1a
		call	bf_setkey_cpys
		;
		ld	hl,bf_setkey_s2a
		call	bf_setkey_cpys
		;
		ld	hl,bf_setkey_s3a
		call	bf_setkey_cpys

		;xor given key to bf_keys array
		pop	bc
		pop	hl
		push	hl
		push	bc

		ld	de,bf_keys
		ld	ixl,18*4
bf_setkey_xorkeys:
		ld	a,[de]
		xor	[hl]
		inc	hl
		ld	[de],a
		inc	e

		djnz	bf_setkey_xk_nowrap
		pop	bc
		pop	hl
		push	hl
		push	bc

bf_setkey_xk_nowrap
		dec	ixl
		jr	nz,bf_setkey_xorkeys

		pop	bc
		pop	bc



		;now recipher all the tables
		ld	hl,bf_tmp
		ld	b,8
		ld	[hl],0
		inc	hl
		djnz	$-3


		ld	b,9
		ld	de,bf_keys
bf_setkey_enckeys
		push	bc
		push	de

		ld	hl,bf_tmp
		ld	d,h
		ld	e,l
		call	bf_encrypt_old

		pop	de

		ld	hl,bf_tmp
		ld	bc,8
		ldir

		pop	bc
		djnz	bf_setkey_enckeys

		ld	hl,s0_b0
		call	bf_setkey_tbli
		ld	hl,s1_b0
		call	bf_setkey_tbld
		ld	hl,s2_b0
		call	bf_setkey_tbli
		ld	hl,s3_b0
		call	bf_setkey_tbld

		call	bf_patchkeys

		ret





bf_setkey_tbli
		push	hl
		ld	hl,bf_tmp
		ld	de,bf_tmp
		call	bf_encrypt_old
		pop	hl

		ld	de,bf_tmp
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	l
		dec	h
		dec	h
		dec	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		dec	h
		dec	h
		dec	h

		inc	l
		jr	nz,bf_setkey_tbli
		ret

bf_setkey_tbld
		push	hl
		ld	hl,bf_tmp
		ld	de,bf_tmp
		call	bf_encrypt_old
		pop	hl

		ld	de,bf_tmp
		ld	a,[de]
		inc	de
		ld	[hl],a
		dec	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		dec	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		dec	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	l
		inc	h
		inc	h
		inc	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		dec	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		dec	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		dec	h
		ld	a,[de]
		inc	de
		ld	[hl],a
		inc	h
		inc	h
		inc	h

		inc	l
		jr	nz,bf_setkey_tbld
		ret


bf_tmp		ds	8








bf_setkey_cpys:

bf_setkey_outer
		push	hl
bf_setkey_inner
		ld	a,[hl]
		inc	hl
		or	a
		jr	z,bf_setkey_inend

		ld	b,a
		ld	a,[de]
		inc	de
		ld	[bc],a
		jr	bf_setkey_inner

bf_setkey_inend
		pop	hl
		inc	c
		jr	nz,bf_setkey_outer
		ret

bf_setkey_s0a:	db	s0_b0/256,s0_b1/256,s0_b2/256,s0_b3/256,0
bf_setkey_s1a:	db	s1_b0/256,s1_b1/256,s1_b2/256,s1_b3/256,0
bf_setkey_s2a:	db	s2_b0/256,s2_b1/256,s2_b2/256,s2_b3/256,0
bf_setkey_s3a:	db	s3_b0/256,s3_b1/256,s3_b2/256,s3_b3/256,0





;OPTIMIZATIONS:
; patch key into the code (then different codes for encrypt and decrypt)
; move key-xor up the flow, so that R after xored with F(L) then xored with key


	macro	bf_enc_old, name, next 

name##L_hh equ $+1
		ld	a,#3e ;xor high L with key
		xor	[hl]
		inc	l
		ld	[next##R_hh],a
		exx
		ld	c,a ;b'c' - s0 box
		exx
name##L_hl equ $+1
		ld	a,#3e
		xor	[hl]
		inc	l
		ld	[next##R_hl],a

		exx	;calc S0+S1

		ld	l,a ;h'l' - s1 box
		ld	b,s0_b3/256
		ld	h,s1_b3/256

		ld	a,[bc]
		dec	b
		add	a,[hl]
		inc	h
		ld	e,a
		ld	a,[bc]
		dec	b
		adc	a,[hl]
		inc	h
		ld	d,a
		ld	a,[bc]
		dec	b
		adc	a,[hl]
		inc	h
		ld	ixl,a
		ld	a,[bc]
		adc	a,[hl]
		inc	h
		ld	b,a
		;b'ixhd'e' - S0+S1
		exx
name##L_lh equ $+1
		ld	a,#3e ;xor low L with key
		xor	[hl]
		inc	l
		ld	[next##R_lh],a
		
		exx	;calc b'ixhd'e'^S2
		ld	l,a
		ld	a,b
		xor	[hl]
		inc	h
		ld	b,a
		ld	a,ixl
		xor	[hl]
		inc	h
		ld	c,a
		ld	a,d
		xor	[hl]
		inc	h
		ld	d,a
		ld	a,e
		xor	[hl]
		inc	h
		ld	e,a
		exx
name##L_ll equ $+1
		ld	a,#3e
		xor	[hl]
		inc	l
		ld	[next##R_ll],a

		exx	;calc b'c'd'e'+S3
		ld	l,a
		ld	a,e
		add	a,[hl]
		inc	h
		ld	e,a
		ld	a,d
		adc	a,[hl]
		inc	h
		ld	d,a
		ld	a,c
		adc	a,[hl]
		inc	h
		ld	c,a
		ld	a,b
		adc	a,[hl] ;F-Function calculated in ac'd'e'
name##R_hh equ $+1
		xor	#ee
		ld	[next##L_hh],a
		ld	a,c
name##R_hl equ $+1
		xor	#ee
		ld	[next##L_hl],a
		ld	a,d
name##R_lh equ $+1
		xor	#ee
		ld	[next##L_lh],a
		ld	a,e
name##R_ll equ $+1
		xor	#ee
		ld	[next##L_ll],a
		exx

	endm





bf_encrypt_old:	;HL - from
		;DE - to

		push	de

		ld	de,r0L_hh
		ldi
		ld	de,r0L_hl
		ldi
		ld	de,r0L_lh
		ldi
		ld	de,r0L_ll
		ldi
		ld	de,r0R_hh
		ldi
		ld	de,r0R_hl
		ldi
		ld	de,r0R_lh
		ldi
		ld	a,[hl]
		ld	[r0R_ll],a




		ld	hl,bf_keys

		bf_enc_old	r0,r1
		bf_enc_old	r1,r2
		bf_enc_old	r2,r3
		bf_enc_old	r3,r4
		bf_enc_old	r4,r5
		bf_enc_old	r5,r6
		bf_enc_old	r6,r7
		bf_enc_old	r7,r8
		bf_enc_old	r8,r9
		bf_enc_old	r9,rA
		bf_enc_old	rA,rB
		bf_enc_old	rB,rC
		bf_enc_old	rC,rD
		bf_enc_old	rD,rE
		bf_enc_old	rE,rF
		bf_enc_old	rF,rfin



		ld	a,4
		add	a,l
		ld	l,a ;K18

		pop	de
rfinR_hh equ $+1
		ld	a,#3e
		xor	[hl]
		inc	l
		ld	[de],a
		inc	de
rfinR_hl equ $+1
		ld	a,#3e
		xor	[hl]
		inc	l
		ld	[de],a
		inc	de
rfinR_lh equ $+1
		ld	a,#3e
		xor	[hl]
		inc	l
		ld	[de],a
		inc	de
rfinR_ll equ $+1
		ld	a,#3e
		xor	[hl]
		ld	[de],a
		inc	de

		ld	a,-7
		add	a,l
		ld	l,a
rfinL_hh equ $+1
		ld	a,#3e
		xor	[hl]
		inc	l
		ld	[de],a
		inc	de
rfinL_hl equ $+1
		ld	a,#3e
		xor	[hl]
		inc	l
		ld	[de],a
		inc	de
rfinL_lh equ $+1
		ld	a,#3e
		xor	[hl]
		inc	l
		ld	[de],a
		inc	de
rfinL_ll equ $+1
		ld	a,#3e
		xor	[hl]
		ld	[de],a

		ret





bf_patchkeys:	ld	hl,key_addrs
		ld	de,bf_keys

		ld	a,18*4

bf_pk_loop	exa

		ld	c,[hl]
		inc	hl
		ld	b,[hl]
		inc	hl

		ld	a,[de]
		inc	de
		ld	[bc],a

		exa
		dec	a
		jr	nz,bf_pk_loop

		ret






key_addrs	dw	presk_0,presk_1,presk_2,presk_3

		dw	r0sk0_0,r0sk0_1,r0sk0_2,r0sk0_3, r0sk1_0,r0sk1_1,r0sk1_2,r0sk1_3
		dw	r1sk0_0,r1sk0_1,r1sk0_2,r1sk0_3, r1sk1_0,r1sk1_1,r1sk1_2,r1sk1_3
		dw	r2sk0_0,r2sk0_1,r2sk0_2,r2sk0_3, r2sk1_0,r2sk1_1,r2sk1_2,r2sk1_3
		dw	r3sk0_0,r3sk0_1,r3sk0_2,r3sk0_3, r3sk1_0,r3sk1_1,r3sk1_2,r3sk1_3
		dw	r4sk0_0,r4sk0_1,r4sk0_2,r4sk0_3, r4sk1_0,r4sk1_1,r4sk1_2,r4sk1_3
		dw	r5sk0_0,r5sk0_1,r5sk0_2,r5sk0_3, r5sk1_0,r5sk1_1,r5sk1_2,r5sk1_3
		dw	r6sk0_0,r6sk0_1,r6sk0_2,r6sk0_3, r6sk1_0,r6sk1_1,r6sk1_2,r6sk1_3
		dw	r7sk0_0,r7sk0_1,r7sk0_2,r7sk0_3, r7sk1_0,r7sk1_1,r7sk1_2,r7sk1_3

		dw	postsk_0,postsk_1,postsk_2,postsk_3


		;L -> bcde, R -> ixiy

	macro	bf_enc, name
		;1st part: use L to calc F, xor it with R and with subkey

		exx
		ld	l,a
		exx
		ld	a,b
		exx
		ld	c,a

		;calc S0+S1
		ld	b,s0_b3/256
		ld	h,s1_b3/256

		ld	a,[bc]
		dec	b
		add	a,[hl]
		inc	h
		ld	e,a
		ld	a,[bc]
		dec	b
		adc	a,[hl]
		inc	h
		ld	d,a
		ld	a,[bc]
		dec	b
		adc	a,[hl]
		inc	h
		exa
		ld	a,[bc]
		add	a,[hl]
		inc	h
		ld	b,a
		exa
		ld	c,a
		jr	nc,$+3
		inc	b
		exx
		;b'c'd'e' -- S0+S1

		ld	a,d
		exx
		ld	l,a

		;calc b'c'd'e'^S2
		ld	a,b
		xor	[hl]
		inc	h
		ld	b,a
		ld	a,c
		xor	[hl]
		inc	h
		ld	c,a
		ld	a,d
		xor	[hl]
		inc	h
		ld	d,a
		ld	a,e
		xor	[hl]
		inc	h
		ld	e,a
		exx
		;b'c'd'e' -- (S0+S1)^S2

		ld	a,e
		exx
		ld	l,a

		;calc b'c'd'e'+S3
		ld	a,e
		add	a,[hl]
		inc	h
		ld	e,a
		ld	a,d
		adc	a,[hl]
		inc	h
		ld	d,a
		ld	a,c
		adc	a,[hl]
		inc	h
		ld	c,a
		ld	a,b
		adc	a,[hl]
		;F calculated in ac'd'e'
		
		;now xor F with R and subkey
		xor	hx
name##sk0_0 equ $+1
		xor	#ee
		ld	hx,a

		ld	a,c
		xor	lx
name##sk0_1 equ $+1
		xor	#ee
		ld	lx,a
		ld	l,a

		ld	a,d
		xor	hy
name##sk0_2 equ $+1
		xor	#ee
		ld	hy,a

		ld	a,e
		xor	ly
name##sk0_3 equ $+1
		xor	#ee
		ld	ly,a ;new R done in ixiy

		;2nd part: use R to calc F, xor it with L and with subkey
		ld	c,hx
		;;;;l is assigned above
		
		ld	b,s0_b3/256
		ld	h,s1_b3/256

		ld	a,[bc]
		dec	b
		add	a,[hl]
		inc	h
		ld	e,a
		ld	a,[bc]
		dec	b
		adc	a,[hl]
		inc	h
		ld	d,a
		ld	a,[bc]
		dec	b
		adc	a,[hl]
		inc	h
		exa
		ld	a,[bc]
		add	a,[hl]
		inc	h
		ld	b,a
		exa
		ld	c,a

		ld	a,hy
		ld	l,a
		adc	a,b
		sub	l
		ld	b,a

		xor	[hl]
		inc	h
		ld	b,a
		ld	a,c
		xor	[hl]
		inc	h
		ld	c,a
		ld	a,d
		xor	[hl]
		inc	h
		ld	d,a
		ld	a,e
		xor	[hl]
		inc	h
				;(S0+S1)^S2 done in b'c'd'a

		ld	e,ly
		ld	l,e

		add	a,[hl]
		inc	h
		ld	e,a
		ld	a,d
		adc	a,[hl]
		inc	h
		ld	d,a
		ld	a,c
		adc	a,[hl]
		inc	h
		ld	c,a
		ld	a,b
		adc	a,[hl]
		;F(R) calculated in ac'd'e'

		exx
		xor	b
name##sk1_0 equ $+1
		xor	#ee
		ld	b,a
		exx
		ld	a,d
		exx
		xor	d
name##sk1_2 equ $+1
		xor	#ee
		ld	d,a
		exx
		ld	a,e
		exx
		xor	e
name##sk1_3 equ $+1
		xor	#ee
		ld	e,a
		exx
		ld	a,c
		exx
		xor	c
name##sk1_1 equ $+1
		xor	#ee
		ld	c,a	;new L done in BCDE
	endm



bf_encrypt:	;HL - from
		;DE - to

		push	de

		ld	a,[hl]
presk_0 equ $+1
		xor	#ee
		ld	b,a
		inc	hl

		ld	a,[hl]
presk_1 equ $+1
		xor	#ee
		ld	c,a
		inc	hl

		ld	a,[hl]
presk_2 equ $+1
		xor	#ee
		ld	d,a
		inc	hl

		ld	a,[hl]
presk_3 equ $+1
		xor	#ee
		ld	e,a
		inc	hl

		ld	a,[hl]
		ld	hx,a
		inc	hl
		ld	a,[hl]
		ld	lx,a
		inc	hl
		ld	a,[hl]
		ld	hy,a
		inc	hl
		ld	a,[hl]
		ld	ly,a
		ld	a,c

		bf_enc	r0
		bf_enc	r1
		bf_enc	r2
		bf_enc	r3
		bf_enc	r4
		bf_enc	r5
		bf_enc	r6
		bf_enc	r7

		pop	hl
		
		
		;now xor R part with the remaining key, store the result as L
		ld	a,hx
postsk_0 equ $+1
		xor	#ee
		ld	[hl],a
		inc	hl
		ld	a,lx
postsk_1 equ $+1
		xor	#ee
		ld	[hl],a
		inc	hl
		ld	a,hy
postsk_2 equ $+1
		xor	#ee
		ld	[hl],a
		inc	hl
		ld	a,ly
postsk_3 equ $+1
		xor	#ee
		ld	[hl],a
		inc	hl

		;store L part as R
		ld	[hl],b
		inc	hl
		ld	[hl],c
		inc	hl
		ld	[hl],d
		inc	hl
		ld	[hl],e

		ret






bf_decrypt	;HL - from
		;DE - to

		ret



bf_ini_keys:
	db	#24,#3F,#6A,#88, #85,#A3,#08,#D3, #13,#19,#8A,#2E, #03,#70,#73,#44
	db	#A4,#09,#38,#22, #29,#9F,#31,#D0, #08,#2E,#FA,#98, #EC,#4E,#6C,#89
	db	#45,#28,#21,#E6, #38,#D0,#13,#77, #BE,#54,#66,#CF, #34,#E9,#0C,#6C
	db	#C0,#AC,#29,#B7, #C9,#7C,#50,#DD, #3F,#84,#D5,#B5, #B5,#47,#09,#17
	db	#92,#16,#D5,#D9, #89,#79,#FB,#1B

bf_ini_s0:
	db	#D1,#31,#0B,#A6, #98,#DF,#B5,#AC, #2F,#FD,#72,#DB, #D0,#1A,#DF,#B7
	db	#B8,#E1,#AF,#ED, #6A,#26,#7E,#96, #BA,#7C,#90,#45, #F1,#2C,#7F,#99
	db	#24,#A1,#99,#47, #B3,#91,#6C,#F7, #08,#01,#F2,#E2, #85,#8E,#FC,#16
	db	#63,#69,#20,#D8, #71,#57,#4E,#69, #A4,#58,#FE,#A3, #F4,#93,#3D,#7E
	db	#0D,#95,#74,#8F, #72,#8E,#B6,#58, #71,#8B,#CD,#58, #82,#15,#4A,#EE
	db	#7B,#54,#A4,#1D, #C2,#5A,#59,#B5, #9C,#30,#D5,#39, #2A,#F2,#60,#13
	db	#C5,#D1,#B0,#23, #28,#60,#85,#F0, #CA,#41,#79,#18, #B8,#DB,#38,#EF
	db	#8E,#79,#DC,#B0, #60,#3A,#18,#0E, #6C,#9E,#0E,#8B, #B0,#1E,#8A,#3E
	db	#D7,#15,#77,#C1, #BD,#31,#4B,#27, #78,#AF,#2F,#DA, #55,#60,#5C,#60
	db	#E6,#55,#25,#F3, #AA,#55,#AB,#94, #57,#48,#98,#62, #63,#E8,#14,#40
	db	#55,#CA,#39,#6A, #2A,#AB,#10,#B6, #B4,#CC,#5C,#34, #11,#41,#E8,#CE
	db	#A1,#54,#86,#AF, #7C,#72,#E9,#93, #B3,#EE,#14,#11, #63,#6F,#BC,#2A
	db	#2B,#A9,#C5,#5D, #74,#18,#31,#F6, #CE,#5C,#3E,#16, #9B,#87,#93,#1E
	db	#AF,#D6,#BA,#33, #6C,#24,#CF,#5C, #7A,#32,#53,#81, #28,#95,#86,#77
	db	#3B,#8F,#48,#98, #6B,#4B,#B9,#AF, #C4,#BF,#E8,#1B, #66,#28,#21,#93
	db	#61,#D8,#09,#CC, #FB,#21,#A9,#91, #48,#7C,#AC,#60, #5D,#EC,#80,#32
	db	#EF,#84,#5D,#5D, #E9,#85,#75,#B1, #DC,#26,#23,#02, #EB,#65,#1B,#88
	db	#23,#89,#3E,#81, #D3,#96,#AC,#C5, #0F,#6D,#6F,#F3, #83,#F4,#42,#39
	db	#2E,#0B,#44,#82, #A4,#84,#20,#04, #69,#C8,#F0,#4A, #9E,#1F,#9B,#5E
	db	#21,#C6,#68,#42, #F6,#E9,#6C,#9A, #67,#0C,#9C,#61, #AB,#D3,#88,#F0
	db	#6A,#51,#A0,#D2, #D8,#54,#2F,#68, #96,#0F,#A7,#28, #AB,#51,#33,#A3
	db	#6E,#EF,#0B,#6C, #13,#7A,#3B,#E4, #BA,#3B,#F0,#50, #7E,#FB,#2A,#98
	db	#A1,#F1,#65,#1D, #39,#AF,#01,#76, #66,#CA,#59,#3E, #82,#43,#0E,#88
	db	#8C,#EE,#86,#19, #45,#6F,#9F,#B4, #7D,#84,#A5,#C3, #3B,#8B,#5E,#BE
	db	#E0,#6F,#75,#D8, #85,#C1,#20,#73, #40,#1A,#44,#9F, #56,#C1,#6A,#A6
	db	#4E,#D3,#AA,#62, #36,#3F,#77,#06, #1B,#FE,#DF,#72, #42,#9B,#02,#3D
	db	#37,#D0,#D7,#24, #D0,#0A,#12,#48, #DB,#0F,#EA,#D3, #49,#F1,#C0,#9B
	db	#07,#53,#72,#C9, #80,#99,#1B,#7B, #25,#D4,#79,#D8, #F6,#E8,#DE,#F7
	db	#E3,#FE,#50,#1A, #B6,#79,#4C,#3B, #97,#6C,#E0,#BD, #04,#C0,#06,#BA
	db	#C1,#A9,#4F,#B6, #40,#9F,#60,#C4, #5E,#5C,#9E,#C2, #19,#6A,#24,#63
	db	#68,#FB,#6F,#AF, #3E,#6C,#53,#B5, #13,#39,#B2,#EB, #3B,#52,#EC,#6F
	db	#6D,#FC,#51,#1F, #9B,#30,#95,#2C, #CC,#81,#45,#44, #AF,#5E,#BD,#09
	db	#BE,#E3,#D0,#04, #DE,#33,#4A,#FD, #66,#0F,#28,#07, #19,#2E,#4B,#B3
	db	#C0,#CB,#A8,#57, #45,#C8,#74,#0F, #D2,#0B,#5F,#39, #B9,#D3,#FB,#DB
	db	#55,#79,#C0,#BD, #1A,#60,#32,#0A, #D6,#A1,#00,#C6, #40,#2C,#72,#79
	db	#67,#9F,#25,#FE, #FB,#1F,#A3,#CC, #8E,#A5,#E9,#F8, #DB,#32,#22,#F8
	db	#3C,#75,#16,#DF, #FD,#61,#6B,#15, #2F,#50,#1E,#C8, #AD,#05,#52,#AB
	db	#32,#3D,#B5,#FA, #FD,#23,#87,#60, #53,#31,#7B,#48, #3E,#00,#DF,#82
	db	#9E,#5C,#57,#BB, #CA,#6F,#8C,#A0, #1A,#87,#56,#2E, #DF,#17,#69,#DB
	db	#D5,#42,#A8,#F6, #28,#7E,#FF,#C3, #AC,#67,#32,#C6, #8C,#4F,#55,#73
	db	#69,#5B,#27,#B0, #BB,#CA,#58,#C8, #E1,#FF,#A3,#5D, #B8,#F0,#11,#A0
	db	#10,#FA,#3D,#98, #FD,#21,#83,#B8, #4A,#FC,#B5,#6C, #2D,#D1,#D3,#5B
	db	#9A,#53,#E4,#79, #B6,#F8,#45,#65, #D2,#8E,#49,#BC, #4B,#FB,#97,#90
	db	#E1,#DD,#F2,#DA, #A4,#CB,#7E,#33, #62,#FB,#13,#41, #CE,#E4,#C6,#E8
	db	#EF,#20,#CA,#DA, #36,#77,#4C,#01, #D0,#7E,#9E,#FE, #2B,#F1,#1F,#B4
	db	#95,#DB,#DA,#4D, #AE,#90,#91,#98, #EA,#AD,#8E,#71, #6B,#93,#D5,#A0
	db	#D0,#8E,#D1,#D0, #AF,#C7,#25,#E0, #8E,#3C,#5B,#2F, #8E,#75,#94,#B7
	db	#8F,#F6,#E2,#FB, #F2,#12,#2B,#64, #88,#88,#B8,#12, #90,#0D,#F0,#1C
	db	#4F,#AD,#5E,#A0, #68,#8F,#C3,#1C, #D1,#CF,#F1,#91, #B3,#A8,#C1,#AD
	db	#2F,#2F,#22,#18, #BE,#0E,#17,#77, #EA,#75,#2D,#FE, #8B,#02,#1F,#A1
	db	#E5,#A0,#CC,#0F, #B5,#6F,#74,#E8, #18,#AC,#F3,#D6, #CE,#89,#E2,#99
	db	#B4,#A8,#4F,#E0, #FD,#13,#E0,#B7, #7C,#C4,#3B,#81, #D2,#AD,#A8,#D9
	db	#16,#5F,#A2,#66, #80,#95,#77,#05, #93,#CC,#73,#14, #21,#1A,#14,#77
	db	#E6,#AD,#20,#65, #77,#B5,#FA,#86, #C7,#54,#42,#F5, #FB,#9D,#35,#CF
	db	#EB,#CD,#AF,#0C, #7B,#3E,#89,#A0, #D6,#41,#1B,#D3, #AE,#1E,#7E,#49
	db	#00,#25,#0E,#2D, #20,#71,#B3,#5E, #22,#68,#00,#BB, #57,#B8,#E0,#AF
	db	#24,#64,#36,#9B, #F0,#09,#B9,#1E, #55,#63,#91,#1D, #59,#DF,#A6,#AA
	db	#78,#C1,#43,#89, #D9,#5A,#53,#7F, #20,#7D,#5B,#A2, #02,#E5,#B9,#C5
	db	#83,#26,#03,#76, #62,#95,#CF,#A9, #11,#C8,#19,#68, #4E,#73,#4A,#41
	db	#B3,#47,#2D,#CA, #7B,#14,#A9,#4A, #1B,#51,#00,#52, #9A,#53,#29,#15
	db	#D6,#0F,#57,#3F, #BC,#9B,#C6,#E4, #2B,#60,#A4,#76, #81,#E6,#74,#00
	db	#08,#BA,#6F,#B5, #57,#1B,#E9,#1F, #F2,#96,#EC,#6B, #2A,#0D,#D9,#15
	db	#B6,#63,#65,#21, #E7,#B9,#F9,#B6, #FF,#34,#05,#2E, #C5,#85,#56,#64
	db	#53,#B0,#2D,#5D, #A9,#9F,#8F,#A1, #08,#BA,#47,#99, #6E,#85,#07,#6A

bf_ini_s1:
	db	#4B,#7A,#70,#E9, #B5,#B3,#29,#44, #DB,#75,#09,#2E, #C4,#19,#26,#23
	db	#AD,#6E,#A6,#B0, #49,#A7,#DF,#7D, #9C,#EE,#60,#B8, #8F,#ED,#B2,#66
	db	#EC,#AA,#8C,#71, #69,#9A,#17,#FF, #56,#64,#52,#6C, #C2,#B1,#9E,#E1
	db	#19,#36,#02,#A5, #75,#09,#4C,#29, #A0,#59,#13,#40, #E4,#18,#3A,#3E
	db	#3F,#54,#98,#9A, #5B,#42,#9D,#65, #6B,#8F,#E4,#D6, #99,#F7,#3F,#D6
	db	#A1,#D2,#9C,#07, #EF,#E8,#30,#F5, #4D,#2D,#38,#E6, #F0,#25,#5D,#C1
	db	#4C,#DD,#20,#86, #84,#70,#EB,#26, #63,#82,#E9,#C6, #02,#1E,#CC,#5E
	db	#09,#68,#6B,#3F, #3E,#BA,#EF,#C9, #3C,#97,#18,#14, #6B,#6A,#70,#A1
	db	#68,#7F,#35,#84, #52,#A0,#E2,#86, #B7,#9C,#53,#05, #AA,#50,#07,#37
	db	#3E,#07,#84,#1C, #7F,#DE,#AE,#5C, #8E,#7D,#44,#EC, #57,#16,#F2,#B8
	db	#B0,#3A,#DA,#37, #F0,#50,#0C,#0D, #F0,#1C,#1F,#04, #02,#00,#B3,#FF
	db	#AE,#0C,#F5,#1A, #3C,#B5,#74,#B2, #25,#83,#7A,#58, #DC,#09,#21,#BD
	db	#D1,#91,#13,#F9, #7C,#A9,#2F,#F6, #94,#32,#47,#73, #22,#F5,#47,#01
	db	#3A,#E5,#E5,#81, #37,#C2,#DA,#DC, #C8,#B5,#76,#34, #9A,#F3,#DD,#A7
	db	#A9,#44,#61,#46, #0F,#D0,#03,#0E, #EC,#C8,#C7,#3E, #A4,#75,#1E,#41
	db	#E2,#38,#CD,#99, #3B,#EA,#0E,#2F, #32,#80,#BB,#A1, #18,#3E,#B3,#31
	db	#4E,#54,#8B,#38, #4F,#6D,#B9,#08, #6F,#42,#0D,#03, #F6,#0A,#04,#BF
	db	#2C,#B8,#12,#90, #24,#97,#7C,#79, #56,#79,#B0,#72, #BC,#AF,#89,#AF
	db	#DE,#9A,#77,#1F, #D9,#93,#08,#10, #B3,#8B,#AE,#12, #DC,#CF,#3F,#2E
	db	#55,#12,#72,#1F, #2E,#6B,#71,#24, #50,#1A,#DD,#E6, #9F,#84,#CD,#87
	db	#7A,#58,#47,#18, #74,#08,#DA,#17, #BC,#9F,#9A,#BC, #E9,#4B,#7D,#8C
	db	#EC,#7A,#EC,#3A, #DB,#85,#1D,#FA, #63,#09,#43,#66, #C4,#64,#C3,#D2
	db	#EF,#1C,#18,#47, #32,#15,#D9,#08, #DD,#43,#3B,#37, #24,#C2,#BA,#16
	db	#12,#A1,#4D,#43, #2A,#65,#C4,#51, #50,#94,#00,#02, #13,#3A,#E4,#DD
	db	#71,#DF,#F8,#9E, #10,#31,#4E,#55, #81,#AC,#77,#D6, #5F,#11,#19,#9B
	db	#04,#35,#56,#F1, #D7,#A3,#C7,#6B, #3C,#11,#18,#3B, #59,#24,#A5,#09
	db	#F2,#8F,#E6,#ED, #97,#F1,#FB,#FA, #9E,#BA,#BF,#2C, #1E,#15,#3C,#6E
	db	#86,#E3,#45,#70, #EA,#E9,#6F,#B1, #86,#0E,#5E,#0A, #5A,#3E,#2A,#B3
	db	#77,#1F,#E7,#1C, #4E,#3D,#06,#FA, #29,#65,#DC,#B9, #99,#E7,#1D,#0F
	db	#80,#3E,#89,#D6, #52,#66,#C8,#25, #2E,#4C,#C9,#78, #9C,#10,#B3,#6A
	db	#C6,#15,#0E,#BA, #94,#E2,#EA,#78, #A5,#FC,#3C,#53, #1E,#0A,#2D,#F4
	db	#F2,#F7,#4E,#A7, #36,#1D,#2B,#3D, #19,#39,#26,#0F, #19,#C2,#79,#60
	db	#52,#23,#A7,#08, #F7,#13,#12,#B6, #EB,#AD,#FE,#6E, #EA,#C3,#1F,#66
	db	#E3,#BC,#45,#95, #A6,#7B,#C8,#83, #B1,#7F,#37,#D1, #01,#8C,#FF,#28
	db	#C3,#32,#DD,#EF, #BE,#6C,#5A,#A5, #65,#58,#21,#85, #68,#AB,#98,#02
	db	#EE,#CE,#A5,#0F, #DB,#2F,#95,#3B, #2A,#EF,#7D,#AD, #5B,#6E,#2F,#84
	db	#15,#21,#B6,#28, #29,#07,#61,#70, #EC,#DD,#47,#75, #61,#9F,#15,#10
	db	#13,#CC,#A8,#30, #EB,#61,#BD,#96, #03,#34,#FE,#1E, #AA,#03,#63,#CF
	db	#B5,#73,#5C,#90, #4C,#70,#A2,#39, #D5,#9E,#9E,#0B, #CB,#AA,#DE,#14
	db	#EE,#CC,#86,#BC, #60,#62,#2C,#A7, #9C,#AB,#5C,#AB, #B2,#F3,#84,#6E
	db	#64,#8B,#1E,#AF, #19,#BD,#F0,#CA, #A0,#23,#69,#B9, #65,#5A,#BB,#50
	db	#40,#68,#5A,#32, #3C,#2A,#B4,#B3, #31,#9E,#E9,#D5, #C0,#21,#B8,#F7
	db	#9B,#54,#0B,#19, #87,#5F,#A0,#99, #95,#F7,#99,#7E, #62,#3D,#7D,#A8
	db	#F8,#37,#88,#9A, #97,#E3,#2D,#77, #11,#ED,#93,#5F, #16,#68,#12,#81
	db	#0E,#35,#88,#29, #C7,#E6,#1F,#D6, #96,#DE,#DF,#A1, #78,#58,#BA,#99
	db	#57,#F5,#84,#A5, #1B,#22,#72,#63, #9B,#83,#C3,#FF, #1A,#C2,#46,#96
	db	#CD,#B3,#0A,#EB, #53,#2E,#30,#54, #8F,#D9,#48,#E4, #6D,#BC,#31,#28
	db	#58,#EB,#F2,#EF, #34,#C6,#FF,#EA, #FE,#28,#ED,#61, #EE,#7C,#3C,#73
	db	#5D,#4A,#14,#D9, #E8,#64,#B7,#E3, #42,#10,#5D,#14, #20,#3E,#13,#E0
	db	#45,#EE,#E2,#B6, #A3,#AA,#AB,#EA, #DB,#6C,#4F,#15, #FA,#CB,#4F,#D0
	db	#C7,#42,#F4,#42, #EF,#6A,#BB,#B5, #65,#4F,#3B,#1D, #41,#CD,#21,#05
	db	#D8,#1E,#79,#9E, #86,#85,#4D,#C7, #E4,#4B,#47,#6A, #3D,#81,#62,#50
	db	#CF,#62,#A1,#F2, #5B,#8D,#26,#46, #FC,#88,#83,#A0, #C1,#C7,#B6,#A3
	db	#7F,#15,#24,#C3, #69,#CB,#74,#92, #47,#84,#8A,#0B, #56,#92,#B2,#85
	db	#09,#5B,#BF,#00, #AD,#19,#48,#9D, #14,#62,#B1,#74, #23,#82,#0E,#00
	db	#58,#42,#8D,#2A, #0C,#55,#F5,#EA, #1D,#AD,#F4,#3E, #23,#3F,#70,#61
	db	#33,#72,#F0,#92, #8D,#93,#7E,#41, #D6,#5F,#EC,#F1, #6C,#22,#3B,#DB
	db	#7C,#DE,#37,#59, #CB,#EE,#74,#60, #40,#85,#F2,#A7, #CE,#77,#32,#6E
	db	#A6,#07,#80,#84, #19,#F8,#50,#9E, #E8,#EF,#D8,#55, #61,#D9,#97,#35
	db	#A9,#69,#A7,#AA, #C5,#0C,#06,#C2, #5A,#04,#AB,#FC, #80,#0B,#CA,#DC
	db	#9E,#44,#7A,#2E, #C3,#45,#34,#84, #FD,#D5,#67,#05, #0E,#1E,#9E,#C9
	db	#DB,#73,#DB,#D3, #10,#55,#88,#CD, #67,#5F,#DA,#79, #E3,#67,#43,#40
	db	#C5,#C4,#34,#65, #71,#3E,#38,#D8, #3D,#28,#F8,#9E, #F1,#6D,#FF,#20
	db	#15,#3E,#21,#E7, #8F,#B0,#3D,#4A, #E6,#E3,#9F,#2B, #DB,#83,#AD,#F7

bf_ini_s2:
	db	#E9,#3D,#5A,#68, #94,#81,#40,#F7, #F6,#4C,#26,#1C, #94,#69,#29,#34
	db	#41,#15,#20,#F7, #76,#02,#D4,#F7, #BC,#F4,#6B,#2E, #D4,#A2,#00,#68
	db	#D4,#08,#24,#71, #33,#20,#F4,#6A, #43,#B7,#D4,#B7, #50,#00,#61,#AF
	db	#1E,#39,#F6,#2E, #97,#24,#45,#46, #14,#21,#4F,#74, #BF,#8B,#88,#40
	db	#4D,#95,#FC,#1D, #96,#B5,#91,#AF, #70,#F4,#DD,#D3, #66,#A0,#2F,#45
	db	#BF,#BC,#09,#EC, #03,#BD,#97,#85, #7F,#AC,#6D,#D0, #31,#CB,#85,#04
	db	#96,#EB,#27,#B3, #55,#FD,#39,#41, #DA,#25,#47,#E6, #AB,#CA,#0A,#9A
	db	#28,#50,#78,#25, #53,#04,#29,#F4, #0A,#2C,#86,#DA, #E9,#B6,#6D,#FB
	db	#68,#DC,#14,#62, #D7,#48,#69,#00, #68,#0E,#C0,#A4, #27,#A1,#8D,#EE
	db	#4F,#3F,#FE,#A2, #E8,#87,#AD,#8C, #B5,#8C,#E0,#06, #7A,#F4,#D6,#B6
	db	#AA,#CE,#1E,#7C, #D3,#37,#5F,#EC, #CE,#78,#A3,#99, #40,#6B,#2A,#42
	db	#20,#FE,#9E,#35, #D9,#F3,#85,#B9, #EE,#39,#D7,#AB, #3B,#12,#4E,#8B
	db	#1D,#C9,#FA,#F7, #4B,#6D,#18,#56, #26,#A3,#66,#31, #EA,#E3,#97,#B2
	db	#3A,#6E,#FA,#74, #DD,#5B,#43,#32, #68,#41,#E7,#F7, #CA,#78,#20,#FB
	db	#FB,#0A,#F5,#4E, #D8,#FE,#B3,#97, #45,#40,#56,#AC, #BA,#48,#95,#27
	db	#55,#53,#3A,#3A, #20,#83,#8D,#87, #FE,#6B,#A9,#B7, #D0,#96,#95,#4B
	db	#55,#A8,#67,#BC, #A1,#15,#9A,#58, #CC,#A9,#29,#63, #99,#E1,#DB,#33
	db	#A6,#2A,#4A,#56, #3F,#31,#25,#F9, #5E,#F4,#7E,#1C, #90,#29,#31,#7C
	db	#FD,#F8,#E8,#02, #04,#27,#2F,#70, #80,#BB,#15,#5C, #05,#28,#2C,#E3
	db	#95,#C1,#15,#48, #E4,#C6,#6D,#22, #48,#C1,#13,#3F, #C7,#0F,#86,#DC
	db	#07,#F9,#C9,#EE, #41,#04,#1F,#0F, #40,#47,#79,#A4, #5D,#88,#6E,#17
	db	#32,#5F,#51,#EB, #D5,#9B,#C0,#D1, #F2,#BC,#C1,#8F, #41,#11,#35,#64
	db	#25,#7B,#78,#34, #60,#2A,#9C,#60, #DF,#F8,#E8,#A3, #1F,#63,#6C,#1B
	db	#0E,#12,#B4,#C2, #02,#E1,#32,#9E, #AF,#66,#4F,#D1, #CA,#D1,#81,#15
	db	#6B,#23,#95,#E0, #33,#3E,#92,#E1, #3B,#24,#0B,#62, #EE,#BE,#B9,#22
	db	#85,#B2,#A2,#0E, #E6,#BA,#0D,#99, #DE,#72,#0C,#8C, #2D,#A2,#F7,#28
	db	#D0,#12,#78,#45, #95,#B7,#94,#FD, #64,#7D,#08,#62, #E7,#CC,#F5,#F0
	db	#54,#49,#A3,#6F, #87,#7D,#48,#FA, #C3,#9D,#FD,#27, #F3,#3E,#8D,#1E
	db	#0A,#47,#63,#41, #99,#2E,#FF,#74, #3A,#6F,#6E,#AB, #F4,#F8,#FD,#37
	db	#A8,#12,#DC,#60, #A1,#EB,#DD,#F8, #99,#1B,#E1,#4C, #DB,#6E,#6B,#0D
	db	#C6,#7B,#55,#10, #6D,#67,#2C,#37, #27,#65,#D4,#3B, #DC,#D0,#E8,#04
	db	#F1,#29,#0D,#C7, #CC,#00,#FF,#A3, #B5,#39,#0F,#92, #69,#0F,#ED,#0B
	db	#66,#7B,#9F,#FB, #CE,#DB,#7D,#9C, #A0,#91,#CF,#0B, #D9,#15,#5E,#A3
	db	#BB,#13,#2F,#88, #51,#5B,#AD,#24, #7B,#94,#79,#BF, #76,#3B,#D6,#EB
	db	#37,#39,#2E,#B3, #CC,#11,#59,#79, #80,#26,#E2,#97, #F4,#2E,#31,#2D
	db	#68,#42,#AD,#A7, #C6,#6A,#2B,#3B, #12,#75,#4C,#CC, #78,#2E,#F1,#1C
	db	#6A,#12,#42,#37, #B7,#92,#51,#E7, #06,#A1,#BB,#E6, #4B,#FB,#63,#50
	db	#1A,#6B,#10,#18, #11,#CA,#ED,#FA, #3D,#25,#BD,#D8, #E2,#E1,#C3,#C9
	db	#44,#42,#16,#59, #0A,#12,#13,#86, #D9,#0C,#EC,#6E, #D5,#AB,#EA,#2A
	db	#64,#AF,#67,#4E, #DA,#86,#A8,#5F, #BE,#BF,#E9,#88, #64,#E4,#C3,#FE
	db	#9D,#BC,#80,#57, #F0,#F7,#C0,#86, #60,#78,#7B,#F8, #60,#03,#60,#4D
	db	#D1,#FD,#83,#46, #F6,#38,#1F,#B0, #77,#45,#AE,#04, #D7,#36,#FC,#CC
	db	#83,#42,#6B,#33, #F0,#1E,#AB,#71, #B0,#80,#41,#87, #3C,#00,#5E,#5F
	db	#77,#A0,#57,#BE, #BD,#E8,#AE,#24, #55,#46,#42,#99, #BF,#58,#2E,#61
	db	#4E,#58,#F4,#8F, #F2,#DD,#FD,#A2, #F4,#74,#EF,#38, #87,#89,#BD,#C2
	db	#53,#66,#F9,#C3, #C8,#B3,#8E,#74, #B4,#75,#F2,#55, #46,#FC,#D9,#B9
	db	#7A,#EB,#26,#61, #8B,#1D,#DF,#84, #84,#6A,#0E,#79, #91,#5F,#95,#E2
	db	#46,#6E,#59,#8E, #20,#B4,#57,#70, #8C,#D5,#55,#91, #C9,#02,#DE,#4C
	db	#B9,#0B,#AC,#E1, #BB,#82,#05,#D0, #11,#A8,#62,#48, #75,#74,#A9,#9E
	db	#B7,#7F,#19,#B6, #E0,#A9,#DC,#09, #66,#2D,#09,#A1, #C4,#32,#46,#33
	db	#E8,#5A,#1F,#02, #09,#F0,#BE,#8C, #4A,#99,#A0,#25, #1D,#6E,#FE,#10
	db	#1A,#B9,#3D,#1D, #0B,#A5,#A4,#DF, #A1,#86,#F2,#0F, #28,#68,#F1,#69
	db	#DC,#B7,#DA,#83, #57,#39,#06,#FE, #A1,#E2,#CE,#9B, #4F,#CD,#7F,#52
	db	#50,#11,#5E,#01, #A7,#06,#83,#FA, #A0,#02,#B5,#C4, #0D,#E6,#D0,#27
	db	#9A,#F8,#8C,#27, #77,#3F,#86,#41, #C3,#60,#4C,#06, #61,#A8,#06,#B5
	db	#F0,#17,#7A,#28, #C0,#F5,#86,#E0, #00,#60,#58,#AA, #30,#DC,#7D,#62
	db	#11,#E6,#9E,#D7, #23,#38,#EA,#63, #53,#C2,#DD,#94, #C2,#C2,#16,#34
	db	#BB,#CB,#EE,#56, #90,#BC,#B6,#DE, #EB,#FC,#7D,#A1, #CE,#59,#1D,#76
	db	#6F,#05,#E4,#09, #4B,#7C,#01,#88, #39,#72,#0A,#3D, #7C,#92,#7C,#24
	db	#86,#E3,#72,#5F, #72,#4D,#9D,#B9, #1A,#C1,#5B,#B4, #D3,#9E,#B8,#FC
	db	#ED,#54,#55,#78, #08,#FC,#A5,#B5, #D8,#3D,#7C,#D3, #4D,#AD,#0F,#C4
	db	#1E,#50,#EF,#5E, #B1,#61,#E6,#F8, #A2,#85,#14,#D9, #6C,#51,#13,#3C
	db	#6F,#D5,#C7,#E7, #56,#E1,#4E,#C4, #36,#2A,#BF,#CE, #DD,#C6,#C8,#37
	db	#D7,#9A,#32,#34, #92,#63,#82,#12, #67,#0E,#FA,#8E, #40,#60,#00,#E0

bf_ini_s3:
	db	#3A,#39,#CE,#37, #D3,#FA,#F5,#CF, #AB,#C2,#77,#37, #5A,#C5,#2D,#1B
	db	#5C,#B0,#67,#9E, #4F,#A3,#37,#42, #D3,#82,#27,#40, #99,#BC,#9B,#BE
	db	#D5,#11,#8E,#9D, #BF,#0F,#73,#15, #D6,#2D,#1C,#7E, #C7,#00,#C4,#7B
	db	#B7,#8C,#1B,#6B, #21,#A1,#90,#45, #B2,#6E,#B1,#BE, #6A,#36,#6E,#B4
	db	#57,#48,#AB,#2F, #BC,#94,#6E,#79, #C6,#A3,#76,#D2, #65,#49,#C2,#C8
	db	#53,#0F,#F8,#EE, #46,#8D,#DE,#7D, #D5,#73,#0A,#1D, #4C,#D0,#4D,#C6
	db	#29,#39,#BB,#DB, #A9,#BA,#46,#50, #AC,#95,#26,#E8, #BE,#5E,#E3,#04
	db	#A1,#FA,#D5,#F0, #6A,#2D,#51,#9A, #63,#EF,#8C,#E2, #9A,#86,#EE,#22
	db	#C0,#89,#C2,#B8, #43,#24,#2E,#F6, #A5,#1E,#03,#AA, #9C,#F2,#D0,#A4
	db	#83,#C0,#61,#BA, #9B,#E9,#6A,#4D, #8F,#E5,#15,#50, #BA,#64,#5B,#D6
	db	#28,#26,#A2,#F9, #A7,#3A,#3A,#E1, #4B,#A9,#95,#86, #EF,#55,#62,#E9
	db	#C7,#2F,#EF,#D3, #F7,#52,#F7,#DA, #3F,#04,#6F,#69, #77,#FA,#0A,#59
	db	#80,#E4,#A9,#15, #87,#B0,#86,#01, #9B,#09,#E6,#AD, #3B,#3E,#E5,#93
	db	#E9,#90,#FD,#5A, #9E,#34,#D7,#97, #2C,#F0,#B7,#D9, #02,#2B,#8B,#51
	db	#96,#D5,#AC,#3A, #01,#7D,#A6,#7D, #D1,#CF,#3E,#D6, #7C,#7D,#2D,#28
	db	#1F,#9F,#25,#CF, #AD,#F2,#B8,#9B, #5A,#D6,#B4,#72, #5A,#88,#F5,#4C
	db	#E0,#29,#AC,#71, #E0,#19,#A5,#E6, #47,#B0,#AC,#FD, #ED,#93,#FA,#9B
	db	#E8,#D3,#C4,#8D, #28,#3B,#57,#CC, #F8,#D5,#66,#29, #79,#13,#2E,#28
	db	#78,#5F,#01,#91, #ED,#75,#60,#55, #F7,#96,#0E,#44, #E3,#D3,#5E,#8C
	db	#15,#05,#6D,#D4, #88,#F4,#6D,#BA, #03,#A1,#61,#25, #05,#64,#F0,#BD
	db	#C3,#EB,#9E,#15, #3C,#90,#57,#A2, #97,#27,#1A,#EC, #A9,#3A,#07,#2A
	db	#1B,#3F,#6D,#9B, #1E,#63,#21,#F5, #F5,#9C,#66,#FB, #26,#DC,#F3,#19
	db	#75,#33,#D9,#28, #B1,#55,#FD,#F5, #03,#56,#34,#82, #8A,#BA,#3C,#BB
	db	#28,#51,#77,#11, #C2,#0A,#D9,#F8, #AB,#CC,#51,#67, #CC,#AD,#92,#5F
	db	#4D,#E8,#17,#51, #38,#30,#DC,#8E, #37,#9D,#58,#62, #93,#20,#F9,#91
	db	#EA,#7A,#90,#C2, #FB,#3E,#7B,#CE, #51,#21,#CE,#64, #77,#4F,#BE,#32
	db	#A8,#B6,#E3,#7E, #C3,#29,#3D,#46, #48,#DE,#53,#69, #64,#13,#E6,#80
	db	#A2,#AE,#08,#10, #DD,#6D,#B2,#24, #69,#85,#2D,#FD, #09,#07,#21,#66
	db	#B3,#9A,#46,#0A, #64,#45,#C0,#DD, #58,#6C,#DE,#CF, #1C,#20,#C8,#AE
	db	#5B,#BE,#F7,#DD, #1B,#58,#8D,#40, #CC,#D2,#01,#7F, #6B,#B4,#E3,#BB
	db	#DD,#A2,#6A,#7E, #3A,#59,#FF,#45, #3E,#35,#0A,#44, #BC,#B4,#CD,#D5
	db	#72,#EA,#CE,#A8, #FA,#64,#84,#BB, #8D,#66,#12,#AE, #BF,#3C,#6F,#47
	db	#D2,#9B,#E4,#63, #54,#2F,#5D,#9E, #AE,#C2,#77,#1B, #F6,#4E,#63,#70
	db	#74,#0E,#0D,#8D, #E7,#5B,#13,#57, #F8,#72,#16,#71, #AF,#53,#7D,#5D
	db	#40,#40,#CB,#08, #4E,#B4,#E2,#CC, #34,#D2,#46,#6A, #01,#15,#AF,#84
	db	#E1,#B0,#04,#28, #95,#98,#3A,#1D, #06,#B8,#9F,#B4, #CE,#6E,#A0,#48
	db	#6F,#3F,#3B,#82, #35,#20,#AB,#82, #01,#1A,#1D,#4B, #27,#72,#27,#F8
	db	#61,#15,#60,#B1, #E7,#93,#3F,#DC, #BB,#3A,#79,#2B, #34,#45,#25,#BD
	db	#A0,#88,#39,#E1, #51,#CE,#79,#4B, #2F,#32,#C9,#B7, #A0,#1F,#BA,#C9
	db	#E0,#1C,#C8,#7E, #BC,#C7,#D1,#F6, #CF,#01,#11,#C3, #A1,#E8,#AA,#C7
	db	#1A,#90,#87,#49, #D4,#4F,#BD,#9A, #D0,#DA,#DE,#CB, #D5,#0A,#DA,#38
	db	#03,#39,#C3,#2A, #C6,#91,#36,#67, #8D,#F9,#31,#7C, #E0,#B1,#2B,#4F
	db	#F7,#9E,#59,#B7, #43,#F5,#BB,#3A, #F2,#D5,#19,#FF, #27,#D9,#45,#9C
	db	#BF,#97,#22,#2C, #15,#E6,#FC,#2A, #0F,#91,#FC,#71, #9B,#94,#15,#25
	db	#FA,#E5,#93,#61, #CE,#B6,#9C,#EB, #C2,#A8,#64,#59, #12,#BA,#A8,#D1
	db	#B6,#C1,#07,#5E, #E3,#05,#6A,#0C, #10,#D2,#50,#65, #CB,#03,#A4,#42
	db	#E0,#EC,#6E,#0E, #16,#98,#DB,#3B, #4C,#98,#A0,#BE, #32,#78,#E9,#64
	db	#9F,#1F,#95,#32, #E0,#D3,#92,#DF, #D3,#A0,#34,#2B, #89,#71,#F2,#1E
	db	#1B,#0A,#74,#41, #4B,#A3,#34,#8C, #C5,#BE,#71,#20, #C3,#76,#32,#D8
	db	#DF,#35,#9F,#8D, #9B,#99,#2F,#2E, #E6,#0B,#6F,#47, #0F,#E3,#F1,#1D
	db	#E5,#4C,#DA,#54, #1E,#DA,#D8,#91, #CE,#62,#79,#CF, #CD,#3E,#7E,#6F
	db	#16,#18,#B1,#66, #FD,#2C,#1D,#05, #84,#8F,#D2,#C5, #F6,#FB,#22,#99
	db	#F5,#23,#F3,#57, #A6,#32,#76,#23, #93,#A8,#35,#31, #56,#CC,#CD,#02
	db	#AC,#F0,#81,#62, #5A,#75,#EB,#B5, #6E,#16,#36,#97, #88,#D2,#73,#CC
	db	#DE,#96,#62,#92, #81,#B9,#49,#D0, #4C,#50,#90,#1B, #71,#C6,#56,#14
	db	#E6,#C6,#C7,#BD, #32,#7A,#14,#0A, #45,#E1,#D0,#06, #C3,#F2,#7B,#9A
	db	#C9,#AA,#53,#FD, #62,#A8,#0F,#00, #BB,#25,#BF,#E2, #35,#BD,#D2,#F6
	db	#71,#12,#69,#05, #B2,#04,#02,#22, #B6,#CB,#CF,#7C, #CD,#76,#9C,#2B
	db	#53,#11,#3E,#C0, #16,#40,#E3,#D3, #38,#AB,#BD,#60, #25,#47,#AD,#F0
	db	#BA,#38,#20,#9C, #F7,#46,#CE,#76, #77,#AF,#A1,#C5, #20,#75,#60,#60
	db	#85,#CB,#FE,#4E, #8A,#E8,#8D,#D8, #7A,#AA,#F9,#B0, #4C,#F9,#AA,#7E
	db	#19,#48,#C2,#5C, #02,#FB,#8A,#8C, #01,#C3,#6A,#E4, #D6,#EB,#E1,#F9
	db	#90,#D4,#F8,#69, #A6,#5C,#DE,#A0, #3F,#09,#25,#2D, #C2,#08,#E6,#9F
	db	#B7,#4E,#61,#32, #CE,#77,#E2,#5B, #57,#8F,#DF,#E3, #3A,#C3,#72,#E6

