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


		; initialize
		org	0
		call	KECCAKI
		halt

		; append byte
		org	#10
		ld	a,[keccak_byte]
		call	KECCAKU
		halt

		; finalize and get result at KECCAKS
		org	#20
		call	KECCAK
		halt


	
		include	"nagy_z80_crypto/keccak.asm"
		include "nagy_z80_crypto/keccaktab.asm"
;KECCAKB:EQU	IOTAT+0x100
;KECCAKS:EQU	KECCAKB+48
;KECCAKP:EQU	KECCAKS+200


		org	#4000
KECCAKB		equ	#4000
KECCAKS		equ	#4100
KECCAKP		equ	#4200

		org	#5000
keccak_byte	equ	#5000


		org	#f000
stack	equ	#0000

