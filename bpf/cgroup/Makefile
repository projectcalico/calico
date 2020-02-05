CFLAGS +=  \
	   -D__KERNEL__ \
	   -D__ASM_SYSREG_H \
	   -D__BPFTOOL_LOADER__ \
	   -DCALI_LOG_LEVEL=CALI_LOG_LEVEL_DEBUG \
	   -DCALI_LOG_PFX=CGROUP \
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

OBJS := connect_balancer.o connect_balancer_v6.o

# cancel the build-in rule
%.o: %.c

all: $(OBJS)

%.ll: %.c %.d Makefile
	$(CC) $(CFLAGS)	-c $< -o $@

%.o: %.ll
	$(LD) -march=bpf -filetype=obj -o $@ $<

.PRECIOUS: %.d

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -M $(CFLAGS) $< > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

include $(OBJS:.o=.d)

clean:
	rm -f *.o *.ll *.d
