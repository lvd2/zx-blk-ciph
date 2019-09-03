EXE = main
OBJS = main.o tests-cipher.o run-test.o z80-wrap.o        \
       my-c-bf.o my-c-aes128.o my-t-aes128.o my-c-speck.o \
       my-z80-aes128.o my-z80-bf.o my-z80-speck.o

GCRYPT ?= 0

ifeq ($(GCRYPT),1)
 OBJS += gcrypt-aes128.o gcrypt-bf.o
endif

CC = gcc
LD = gcc

CFLAGS = -O3 -g3 -ggdb -std=gnu99

ifeq ($(GCRYPT),1)
 CFLAGS += -DGCRYPT
endif


LDFLAGS = -Llibz80 -lz80

ifeq ($(GCRYPT),1)
 LDFLAGS += -lgcrypt
endif

LDFLAGS += -Wl,-rpath,libz80 


SUBDIRS = z80



.PHONY: all clean subdirs $(SUBDIRS)

all: $(EXE) subdirs

main.o: main.c Makefile ciph-common.h my-c-bf.h my-c-aes128.h my-t-aes128.h my-z80-aes128.h my-z80-bf.h my-z80-speck.h run-test.h tests-cipher.h gcrypt-bf.h gcrypt-aes128.h
	$(CC) $(CFLAGS) -c $< -o $@




my-c-bf.o: my-c-bf.c Makefile ciph-common.h my-c-bf.h
	$(CC) $(CFLAGS) -c $< -o $@

my-c-aes128.o: my-c-aes128.c Makefile ciph-common.h my-c-aes128.h
	$(CC) $(CFLAGS) -c $< -o $@

my-t-aes128.o: my-t-aes128.c Makefile ciph-common.h my-t-aes128.h
	$(CC) $(CFLAGS) -c $< -o $@

my-c-speck.o: my-c-speck.c Makefile ciph-common.h my-c-speck.h
	$(CC) $(CFLAGS) -c $< -o $@




my-z80-aes128.o: my-z80-aes128.c Makefile ciph-common.h my-z80-aes128.h z80-wrap.h
	$(CC) $(CFLAGS) -c $< -o $@

my-z80-bf.o: my-z80-bf.c Makefile my-z80-bf.h ciph-common.h z80-wrap.h
	$(CC) $(CFLAGS) -c $< -o $@

my-z80-speck.o: my-z80-speck.c Makefile my-z80-speck.h ciph-common.h z80-wrap.h
	$(CC) $(CFLAGS) -c $< -o $@


z80-wrap.o: z80-wrap.c Makefile z80-wrap.h
	$(CC) $(CFLAGS) -c $< -o $@



gcrypt-aes128.o: gcrypt-aes128.c Makefile gcrypt-aes128.h ciph-common.h
	$(CC) $(CFLAGS) -c $< -o $@

gcrypt-bf.o: gcrypt-bf.c Makefile gcrypt-bf.h ciph-common.h
	$(CC) $(CFLAGS) -c $< -o $@






tests-cipher.o: tests-cipher.c Makefile tests-cipher.h
	$(CC) $(CFLAGS) -c $< -o $@

run-test.o: run-test.c Makefile run-test.h ciph-common.h tests-cipher.h
	$(CC) $(CFLAGS) -c $< -o $@






$(EXE): Makefile $(OBJS) $(Z80_BINS)
	$(LD) $(OBJS) $(LDFLAGS) -o $@



subdirs: $(SUBDIRS)


$(SUBDIRS):
	make -C $@



clean:
	rm *.o $(EXE)
#	rm $(OBJS) $(EXE)

