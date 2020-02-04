# Disable implicit rules.
.SUFFIXES:

CFLAGS +=  \
	-x c \
	-D__KERNEL__ \
	-D__ASM_SYSREG_H \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wunused \
	-Wall \
	-Werror \
	-fno-stack-protector \
	-O2 \
	-emit-llvm

CC := clang
LD := llc

OBJS:=$(shell ./gen-objs)
C_FILES:=tc.c connect_balancer.c

# cancel the build-in rule
%.o: %.c

all: $(OBJS)

connect_time%.ll: connect_balancer.c connect_balancer.d
	$(CC) $(CFLAGS) `./calculate-flags $@` -c $< -o $@

from%.ll: tc.c tc.d
	$(CC) $(CFLAGS) `./calculate-flags $@` -c $< -o $@

to%.ll: tc.c tc.d
	$(CC) $(CFLAGS) `./calculate-flags $@` -c $< -o $@

bin/%.o: %.ll | bin
	$(LD) -march=bpf -filetype=obj -o $@ $<

bin:
	mkdir -p bin

.PRECIOUS: %.d

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -M $(CFLAGS) $< > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

D_FILES=$(C_FILES:.c=.d)
include $(D_FILES)

clean:
	rm -f *.o *.ll *.d bin/*
