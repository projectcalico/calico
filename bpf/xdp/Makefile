CFLAGS +=  \
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

OBJS := redir_tc.o

# cancel the build-in rule
%.o: %.c

all: $(OBJS)

%.ll: %.c %.d
	$(CC) $(CFLAGS)	-c $< -o $@

%.o: %.ll
	$(LD) -march=bpf -filetype=obj -o $@ $<

.PRECIOUS: %.d

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

include $(OBJS:.o=.d)

clean:
	rm -f *.o *.ll *.d
