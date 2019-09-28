AES_SRCS=aes.asm aes_test.asm
AES_BIN=aes_test.bin

BF_SRCS=bf.asm bf_test.asm
BF_BIN=bf_test.bin

SPECK_SRCS=speck.asm speck_test.asm
SPECK_BIN=speck_test.bin

KECCAK_SRCS=nagy_keccak_test.asm nagy_z80_crypto/keccak.asm
KECCAK_BIN=nagy_keccak_test.bin

ASM=../pasmo/pasmo

all: $(AES_BIN) $(BF_BIN) $(SPECK_BIN) $(KECCAK_BIN)

clean:
	rm $(AES_BIN) $(BF_BIN) $(SPECK_BIN) $(KECCAK_BIN)

$(AES_BIN): $(AES_SRCS)
	$(ASM) aes_test.asm $(AES_BIN)

$(BF_BIN): $(BF_SRCS)
	$(ASM) bf_test.asm $(BF_BIN)

$(SPECK_BIN): $(SPECK_SRCS)
	$(ASM) speck_test.asm $(SPECK_BIN)

$(KECCAK_BIN): $(KECCAK_SRCS)
	$(ASM) -I nagy_z80_crypto nagy_keccak_test.asm $(KECCAK_BIN)

