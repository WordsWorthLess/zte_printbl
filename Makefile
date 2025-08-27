CC_ARM := arm-linux-gnueabi-gcc
CC_ARM_HF := arm-linux-gnueabihf-gcc
CC_MIPS := mips-linux-gnu-gcc

CFLAGS := -O2 -Wall
LDFLAGS := -ldl -Wl,--export-dynamic
ARM_FLAGS := -marm

all: ptbl ptbl_hf ptbl_mips

ptbl: ptbl.c
	$(CC_ARM) $(CFLAGS) $(ARM_FLAGS) $< -o $@ $(LDFLAGS)

ptbl_hf: ptbl.c
	$(CC_ARM_HF) $(CFLAGS) $(ARM_FLAGS) $< -o $@ $(LDFLAGS)

ptbl_mips: ptbl.c
	$(CC_MIPS) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f ptbl ptbl_hf ptbl_mips

.PHONY: all clean
