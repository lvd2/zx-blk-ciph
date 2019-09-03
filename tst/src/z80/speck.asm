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


		;Z80 speck

		;L is bchxlx initially
		;R is dehl
		;key is patched into the code

		;ROR 8 is not done, instead 4 carrying registers are constantly rotated in each iteration


	macro	speck_enc, Lhh, Lhl, Llh, Lll, mode, lbl

;OPTIMIZATIONS: once per 2 rounds we might do direct ADD IX,DE addition below (dimkam),
;               either in upper or lower part

		;add R to L
 IF mode=1
		exd
		add	ix,de
		exd
 ELSE
		ld	a,Lll
		add	a,l
		ld	Lll,a

		ld	a,Llh
		adc	a,h
		ld	Llh,a
 ENDIF

 IF mode=2
		jr	nc,$+4
		inc	ix
		add	ix,de

		;xor L with key
  IF NOT NUL lbl
lbl##Khh equ $+1
  ENDIF
		ld	a,#3e
		xor	Lhh
		ld	Lhh,a
 ELSE
		ld	a,Lhl
		adc	a,e
		ld	Lhl,a

		ld	a,Lhh
		adc	a,d
		;xor L with key
  IF NOT NUL lbl
lbl##Khh equ $+1
  ENDIF
		xor	#ee
		ld	Lhh,a
 ENDIF


 IF NOT NUL lbl
lbl##Khl equ $+1
 ENDIF
		ld	a,#3e
		xor	Lhl
		ld	Lhl,a

 IF NOT NUL lbl
lbl##Klh equ $+1
 ENDIF
		ld	a,#3e
		xor	Llh
		ld	Llh,a

 IF NOT NUL lbl
lbl##Kll equ $+1
 ENDIF
		ld	a,#3e
		xor	Lll
		ld	Lll,a

		;ROL 3 of R
		ld	a,l

		add	hl,hl
		rl	e
		rl	d
		rla

		add	hl,hl
		rl	e
		rl	d
		rla

		add	hl,hl
		rl	e
		rl	d
		rla

		;xor L with R
		xor	Lll
		ld	l,a 


		ld	a,h
		xor	Llh
		ld	h,a
		ld	a,e
		xor	Lhl
		ld	e,a
		ld	a,d
		xor	Lhh
		ld	d,a
	endm







speck_setkey:	;HL - key (128bit)

		ld	de,speck_kbuf
		ld	bc,16
		ldir



		ld	hy,0
		ld	hl,sp_keys
		exx

		ld	hl,[speck_kbuf+0]
		ld	de,[speck_kbuf+2]
speck_sk_loop:
		call	speck_sk_subkey

		ld	ix,[speck_kbuf+4]
		ld	bc,[speck_kbuf+6]
		call	speck_sk_iteration
		ld	[speck_kbuf+4],ix
		ld	[speck_kbuf+6],bc
		inc	hy

		call	speck_sk_subkey


		ld	ix,[speck_kbuf+8]
		ld	bc,[speck_kbuf+10]
		call	speck_sk_iteration
		ld	[speck_kbuf+8],ix
		ld	[speck_kbuf+10],bc
		inc	hy
		
		call	speck_sk_subkey


		ld	ix,[speck_kbuf+12] ;the very last sk_iteration in the last loop pass is actually useless
		ld	bc,[speck_kbuf+14]
		call	speck_sk_iteration
		ld	[speck_kbuf+12],ix
		ld	[speck_kbuf+14],bc
		inc	hy


		ld	a,hy
		cp	27
		jr	c,speck_sk_loop



		;patch the subkeys in the code
		ld	hl,speck_sks
		ld	de,sp_keys
		ld	lx,27*4
speck_sk_set
		ld	c,[hl]
		inc	hl
		ld	b,[hl]
		inc	hl
		ld	a,[de]
		inc	e
		ld	[bc],a
		dec	lx
		jr	nz,speck_sk_set

		ret


speck_sk_subkey:
		push	de
		push	hl
		exx
		pop	bc
		ld	[hl],c
		inc	l
		ld	[hl],b
		inc	l
		pop	bc
		ld	[hl],c
		inc	l
		ld	[hl],b
		inc	l
		exx
		ret


speck_sk_iteration:
		;bcix is LEFT part (the one iterated over the array of 3 last parts of the key)
		;dehl is RIGHT part (the one actually goes as subkey, initially first part of the key)

		;make ROR 8 for left part
		ld	a,lx
		ld	lx,hx
		ld	hx,c
		ld	c,b
		ld	b,a

		;add R to L
		exd
		add	ix,de
		exd

		ld	a,c
		adc	a,e
		ld	c,a

		ld	a,b
		adc	a,d
		ld	b,a
		

		;xor L with subkey index
		ld	a,hy
		xor	lx
		ld	lx,a

		;ROR 3 for R
		xor	a

		add	hl,hl
		rl	e
		rl	d
		rla
		add	hl,hl
		rl	e
		rl	d
		rla
		add	hl,hl
		rl	e
		rl	d
		rla
		or	l

		;xor R with L
		xor	lx
		ld	l,a
		ld	a,h
		xor	hx
		ld	h,a
		ld	a,e
		xor	c
		ld	e,a
		ld	a,d
		xor	b
		ld	d,a

		ret

speck_sks	
		dw	SE00Kll,SE00Klh,SE00Khl,SE00Khh
		dw	SE01Kll,SE01Klh,SE01Khl,SE01Khh
		dw	SE02Kll,SE02Klh,SE02Khl,SE02Khh
		dw	SE03Kll,SE03Klh,SE03Khl,SE03Khh
		dw	SE04Kll,SE04Klh,SE04Khl,SE04Khh
		dw	SE05Kll,SE05Klh,SE05Khl,SE05Khh
		dw	SE06Kll,SE06Klh,SE06Khl,SE06Khh
		dw	SE07Kll,SE07Klh,SE07Khl,SE07Khh
		dw	SE08Kll,SE08Klh,SE08Khl,SE08Khh
		dw	SE09Kll,SE09Klh,SE09Khl,SE09Khh
		dw	SE10Kll,SE10Klh,SE10Khl,SE10Khh
		dw	SE11Kll,SE11Klh,SE11Khl,SE11Khh
		dw	SE12Kll,SE12Klh,SE12Khl,SE12Khh
		dw	SE13Kll,SE13Klh,SE13Khl,SE13Khh
		dw	SE14Kll,SE14Klh,SE14Khl,SE14Khh
		dw	SE15Kll,SE15Klh,SE15Khl,SE15Khh
		dw	SE16Kll,SE16Klh,SE16Khl,SE16Khh
		dw	SE17Kll,SE17Klh,SE17Khl,SE17Khh
		dw	SE18Kll,SE18Klh,SE18Khl,SE18Khh
		dw	SE19Kll,SE19Klh,SE19Khl,SE19Khh
		dw	SE20Kll,SE20Klh,SE20Khl,SE20Khh
		dw	SE21Kll,SE21Klh,SE21Khl,SE21Khh
		dw	SE22Kll,SE22Klh,SE22Khl,SE22Khh
		dw	SE23Kll,SE23Klh,SE23Khl,SE23Khh
		dw	SE24Kll,SE24Klh,SE24Khl,SE24Khh
		dw	SE25Kll,SE25Klh,SE25Khl,SE25Khh
		dw	SE26Kll,SE26Klh,SE26Khl,SE26Khh


speck_kbuf	ds	16










speck_encrypt:	;HL - src, DE - dst

		;fetch R (dehl), then L (bcix), LE both

		push	de
		push	hl
		inc	hl
		inc	hl
		ld	e,[hl]
		inc	hl
		ld	d,[hl]
		inc	hl
		ld	a,[hl]
		ld	lx,a
		inc	hl
		ld	a,[hl]
		ld	hx,a
		inc	hl
		ld	c,[hl]
		inc	hl
		ld	b,[hl]
		pop	hl
		ld	a,[hl]
		inc	hl
		ld	h,[hl]
		ld	l,a
		
		; bcix - L, dehl - R
		speck_enc	lx,b,c,hx,0,SE00


		speck_enc	hx,lx,b,c,2,SE01
		speck_enc	c,hx,lx,b,0,SE02
		speck_enc	b,c,hx,lx,1,SE03
		speck_enc	lx,b,c,hx,0,SE04
	
		speck_enc	hx,lx,b,c,2,SE05
		speck_enc	c,hx,lx,b,0,SE06
		speck_enc	b,c,hx,lx,1,SE07
		speck_enc	lx,b,c,hx,0,SE08
	
		speck_enc	hx,lx,b,c,2,SE09
		speck_enc	c,hx,lx,b,0,SE10
		speck_enc	b,c,hx,lx,1,SE11
		speck_enc	lx,b,c,hx,0,SE12
	
		speck_enc	hx,lx,b,c,2,SE13
		speck_enc	c,hx,lx,b,0,SE14
		speck_enc	b,c,hx,lx,1,SE15
		speck_enc	lx,b,c,hx,0,SE16
	
		speck_enc	hx,lx,b,c,2,SE17
		speck_enc	c,hx,lx,b,0,SE18
		speck_enc	b,c,hx,lx,1,SE19
		speck_enc	lx,b,c,hx,0,SE20
	
		speck_enc	hx,lx,b,c,2,SE21
		speck_enc	c,hx,lx,b,0,SE22
		speck_enc	b,c,hx,lx,1,SE23
		speck_enc	lx,b,c,hx,0,SE24


		speck_enc	hx,lx,b,c,2,SE25
		speck_enc	c,hx,lx,b,0,SE26
		;L now in chxlxb

		ld	a,h
		exa
		ld	a,l
		pop	hl
		ld	[hl],a
		inc	hl
		exa
		ld	[hl],a
		inc	hl
		ld	[hl],e
		inc	hl
		ld	[hl],d
		inc	hl
		ld	[hl],b
		inc	hl
		ld	a,lx
		ld	[hl],a
		inc	hl
		ld	a,hx
		ld	[hl],a
		inc	hl
		ld	[hl],c
		ret



speck_decrypt:	;HL - src, DE - dst
		ret




