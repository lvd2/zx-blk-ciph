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

		org	0
		call	aes_init
		halt

		org	#10
		ld	hl,inkey
		call	aes_setkey
		halt

		org	#20
		ld	hl,indata
		ld	de,outdata
		call	aes_encrypt
		halt


	
		include	"aes.asm"




		org	#4000
sbox	equ	#4000 ;IN
box02	equ	#4100 ;  THIS
box03	equ	#4200 ;      ORDER!

		org	#5000
keys	equ	#5000
state	equ	#50C0 ;32(!) bytes

		org	#6000
inkey	equ	#6000
indata	equ	#6100
outdata	equ	#6200



		org	#f000
stack	equ	#0000

