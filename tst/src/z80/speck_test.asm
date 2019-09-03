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
		ld	hl,sp_inkey
		call	speck_setkey
		halt

		org	#10
		ld	hl,sp_indata
		ld	de,sp_outdata
		call	speck_encrypt
		halt

		org	#20
		ld	hl,sp_indata
		ld	de,sp_outdata
		call	speck_decrypt
		halt

		org	#30
		halt

	
		include	"speck.asm"




		org	#4000
sp_inkey	equ	#4000
sp_keys		equ	#4100


		org	#5000
sp_state 	equ	#5000

		org	#6000
sp_indata	equ	#6000
sp_outdata	equ	#6100

		org	#f000
stack	equ	#0000

