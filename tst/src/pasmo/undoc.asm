; undoc.asm
; Test of assembling of undocumented z80 instructions.

	org 100h ; For tests with cp/m

	ld a,ixh
	ld a,ixl
	ld a,iyh
	ld a,iyl

	ld b,ixh
	ld b,ixl
	ld b,iyh
	ld b,iyl

	ld c,ixh
	ld c,ixl
	ld c,iyh
	ld c,iyl

	ld d,ixh
	ld d,ixl
	ld d,iyh
	ld d,iyl

	ld e,ixh
	ld e,ixl
	ld e,iyh
	ld e,iyl

	ld ixh,a
	ld ixh,b
	ld ixh,c
	ld ixh,d
	ld ixh,e
	ld ixh,ixh
	ld ixh,ixl
	ld ixh,20h

	ld ixl,a
	ld ixl,b
	ld ixl,c
	ld ixl,d
	ld ixl,e
	ld ixl,ixh
	ld ixl,ixl
	ld ixl,20h

	ld iyh,a
	ld iyh,b
	ld iyh,c
	ld iyh,d
	ld iyh,e
	ld iyh,iyh
	ld iyh,iyl
	ld iyh,20h

	ld iyl,a
	ld iyl,b
	ld iyl,c
	ld iyl,d
	ld iyl,e
	ld iyl,iyh
	ld iyl,iyl
	ld iyl,20h

	inc ixh
	inc ixl
	inc iyh
	inc iyl
	dec ixh
	dec ixl
	dec iyh
	dec iyl

	add a,ixh
	add a,ixl
	add a,iyh
	add a,iyl

	adc a,ixh
	adc a,ixl
	adc a,iyh
	adc a,iyl

	sbc a, ixh
	sbc a, ixl
	sbc a, iyh
	sbc a, iyl

	sub ixh
	sub ixl
	sub iyh
	sub iyl

	and ixh
	and ixl
	and iyh
	and iyl

	xor ixh
	xor ixl
	xor iyh
	xor iyl

	or ixh
	or ixl
	or iyh
	or iyl

	cp ixh
	cp ixl
	cp iyh
	cp iyl

	sll a
	sll b
	sll c
	sll d
	sll e
	sll h
	sll l
	sll (hl)

	sll (ix+20h)
	sll (iy+20h)




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	ld a,xh
	ld a,xl
	ld a,yh
	ld a,yl
	ld b,xh
	ld b,xl
	ld b,yh
	ld b,yl
	ld c,xh
	ld c,xl
	ld c,yh
	ld c,yl
	ld d,xh
	ld d,xl
	ld d,yh
	ld d,yl
	ld e,xh
	ld e,xl
	ld e,yh
	ld e,yl
	ld xh,a
	ld xh,b
	ld xh,c
	ld xh,d
	ld xh,e
	ld xh,xh
	ld xh,xl
	ld xh,20h
	ld xl,a
	ld xl,b
	ld xl,c
	ld xl,d
	ld xl,e
	ld xl,xh
	ld xl,xl
	ld xl,20h
	ld yh,a
	ld yh,b
	ld yh,c
	ld yh,d
	ld yh,e
	ld yh,yh
	ld yh,yl
	ld yh,20h
	ld yl,a
	ld yl,b
	ld yl,c
	ld yl,d
	ld yl,e
	ld yl,yh
	ld yl,yl
	ld yl,20h
	inc xh
	inc xl
	inc yh
	inc yl
	dec xh
	dec xl
	dec yh
	dec yl
	add a,xh
	add a,xl
	add a,yh
	add a,yl
	adc a,xh
	adc a,xl
	adc a,yh
	adc a,yl
	sbc a, xh
	sbc a, xl
	sbc a, yh
	sbc a, yl
	sub xh
	sub xl
	sub yh
	sub yl
	and xh
	and xl
	and yh
	and yl
	xor xh
	xor xl
	xor yh
	xor yl
	or xh
	or xl
	or yh
	or yl
	cp xh
	cp xl
	cp yh
	cp yl
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	ld a,hx
	ld a,lx
	ld a,hy
	ld a,ly
	ld b,hx
	ld b,lx
	ld b,hy
	ld b,ly
	ld c,hx
	ld c,lx
	ld c,hy
	ld c,ly
	ld d,hx
	ld d,lx
	ld d,hy
	ld d,ly
	ld e,hx
	ld e,lx
	ld e,hy
	ld e,ly
	ld hx,a
	ld hx,b
	ld hx,c
	ld hx,d
	ld hx,e
	ld hx,hx
	ld hx,lx
	ld hx,20h
	ld lx,a
	ld lx,b
	ld lx,c
	ld lx,d
	ld lx,e
	ld lx,hx
	ld lx,lx
	ld lx,20h
	ld hy,a
	ld hy,b
	ld hy,c
	ld hy,d
	ld hy,e
	ld hy,hy
	ld hy,ly
	ld hy,20h
	ld ly,a
	ld ly,b
	ld ly,c
	ld ly,d
	ld ly,e
	ld ly,hy
	ld ly,ly
	ld ly,20h
	inc hx
	inc lx
	inc hy
	inc ly
	dec hx
	dec lx
	dec hy
	dec ly
	add a,hx
	add a,lx
	add a,hy
	add a,ly
	adc a,hx
	adc a,lx
	adc a,hy
	adc a,ly
	sbc a, hx
	sbc a, lx
	sbc a, hy
	sbc a, ly
	sub hx
	sub lx
	sub hy
	sub ly
	and hx
	and lx
	and hy
	and ly
	xor hx
	xor lx
	xor hy
	xor ly
	or hx
	or lx
	or hy
	or ly
	cp hx
	cp lx
	cp hy
	cp ly

	end
