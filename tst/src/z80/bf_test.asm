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

		org	#00
		ld	hl,bf_inkey
		ld	a,[bf_inkey_len]
		call	bf_setkey
		halt

		org	#10
		ld	hl,bf_indata
		ld	de,bf_outdata
		call	bf_encrypt
		halt

		org	#20
		ld	hl,bf_indata
		ld	de,bf_outdata
		call	bf_decrypt
		halt

		org	#30
		halt

	
		include	"bf.asm"




		org	#4000
s0_b0	equ	#4000
s0_b1	equ	#4100
s0_b2	equ	#4200
s0_b3	equ	#4300

s1_b3	equ	#4400
s1_b2	equ	#4500
s1_b1	equ	#4600
s1_b0	equ	#4700

s2_b0	equ	#4800
s2_b1	equ	#4900
s2_b2	equ	#4A00
s2_b3	equ	#4B00

s3_b3	equ	#4C00
s3_b2	equ	#4D00
s3_b1	equ	#4E00
s3_b0	equ	#4F00

bf_keys		equ	#5000


		org	#6000
bf_state equ	#6000

		org	#7000
bf_inkey	equ	#7000
bf_indata	equ	#7100
bf_outdata	equ	#7200

bf_inkey_len	equ	#7300


		org	#f000
stack	equ	#0000

