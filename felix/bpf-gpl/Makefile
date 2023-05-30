# Project Calico BPF dataplane build scripts.
# Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# Disable implicit rules.
.SUFFIXES:

# C flags for compiling BPF programs. "-target bpf" enables some workarounds
# for BPF programs and makes inline assembly aware of the BPF registers.
CFLAGS +=  \
	-Wall \
	-Werror \
	-fno-stack-protector \
	-O2 \
	-target bpf \
	-emit-llvm \
	-g

# Build against libbpf and its recent copy of the kernel headers.
# We link against the user API version of the headers because they contain
# everything we need for now.
#
# Note: for headers that aren't in the libbpf include directory, we'll
# fall back on the system-installed headers. At time of writing, the versions
# of those in the go-build container are from a v4.19 kernel, which is
# older than we'd like (BPF mode went GA with v5.2 as the target). It's
# not ideal to mix headers in this way but the structure of the headers
# hasn't changed enough since v4.19 to cause problems yet (and, when
# go-build eventually gets revved to the next version of Debian, the
# situation should get better, not worse).
#
# The "proper" fix for this is to rebase go-build onto a more recent
# distribution with the right kernel headers and recent libbpf package.
# That's tricky because go-build is based on the upstream images
# from the go team, and they don't provide anything newer.
CFLAGS +=  \
	-I ./include/libbpf/src/ \
	-I ./include/libbpf/include/uapi

# Workaround for Debian placing "asm/types.h" in /usr/include/x86_64-linux-gnu
# We also pick up a couple of other definitions from here, such as the socket
# type constants (which are architecture dependent for historical reasons).
TRIPLET := $(shell gcc -dumpmachine)
CFLAGS += -I/usr/include/$(TRIPLET)

CC := clang-12
LD := llc-12

UT_C_FILES:=$(shell find ut -name '*.c')
UT_OBJS:=$(UT_C_FILES:.c=.o) $(shell ./list-ut-objs)

OBJS:=$(shell ./list-objs)
OBJS+=bin/tc_preamble.o
OBJS+=bin/xdp_preamble.o
OBJS+=bin/policy_default.o
C_FILES:=tc_preamble.c tc.c connect_balancer.c connect_balancer_v6.c xdp_preamble.c xdp.c policy_default.c

all: $(OBJS)
ut-objs: $(UT_OBJS)

COMPILE=$(CC) $(CFLAGS) `./calculate-flags $@` -c $< -o $@
connect_time_%v4.ll: connect_balancer.c connect_balancer.d calculate-flags
	$(COMPILE)
connect_time_%v6.ll: connect_balancer_v6.c connect_balancer_v6.d calculate-flags
	$(COMPILE)

UT_CFLAGS=\
	-D__BPFTOOL_LOADER__ \
	-DCALI_LOG_LEVEL=CALI_LOG_LEVEL_DEBUG \
	-DUNITTEST \
	-DCALI_LOG_PFX=UNITTEST \
	-I .

# Mini-UT programs that test one or two functions.  These are each in their own files.
ut/%.ll: ut/%.c ut/ut.h tc.c tc.d
	$(CC) $(UT_CFLAGS) $(CFLAGS) -c $< -o $@

tc_preamble.ll: tc_preamble.c tc_preamble.d
	$(CC) $(CFLAGS) -c $< -o $@

xdp_preamble.ll: xdp_preamble.c xdp_preamble.d
	$(CC) $(CFLAGS) -DCALI_COMPILE_FLAGS=64 -c $< -o $@

policy_default.ll: policy_default.c policy_default.d
	$(CC) $(CFLAGS) -c $< -o $@

# Production and UT versions of the main binaries.
# Combining the targets into one rule causes make to fail to rebuild the .ll files.  Not sure why.
to%.ll: tc.c tc.d calculate-flags
	$(COMPILE)
from%.ll: tc.c tc.d calculate-flags
	$(COMPILE)
#to%_v6.ll: tc6.c tc.d calculate-flags
#	$(COMPILE)
#from%_v6.ll: tc6.c tc.d calculate-flags
#	$(COMPILE)
test%.ll: tc.c tc.d calculate-flags
	$(COMPILE)
#test%_v6.ll: tc6.c tc.d calculate-flags
#	$(COMPILE)
xdp%.ll: xdp.c xdp.d calculate-flags
	$(COMPILE)
test_xdp%.ll: xdp.c xdp.d calculate-flags
	$(COMPILE)

LINK=$(LD) -march=bpf -filetype=obj -o $@ $<
bin/tc_preamble.o: tc_preamble.ll | bin
	$(LINK)
bin/xdp_preamble.o: xdp_preamble.ll | bin
	$(LINK)
bin/policy_default.o: policy_default.ll | bin
	$(LINK)
bin/to%.o: to%.ll | bin
	$(LINK)
bin/from%.o: from%.ll | bin
	$(LINK)
bin/test%.o: test%.ll | bin
	$(LINK)
bin/xdp%.o: xdp%.ll | bin
	$(LINK)
bin/connect_time_%v4.o: connect_time_%v4.ll | bin
	$(LINK)
bin/connect_time_%v6.o: connect_time_%v6.ll | bin
	$(LINK)
bin/connect_time_%v4_co-re.o: connect_time_%v4.ll | bin
	$(LINK)
bin/connect_time_%v6_co-re.o: connect_time_%v6.ll | bin
	$(LINK)
ut/%.o: ut/%.ll
	$(LINK)

bin:
	mkdir -p bin

.PRECIOUS: %.d

%.d: %.c
	set -e; rm -f $@; \
		$(CC) -M $(CFLAGS) $< > $@.$$$$ || { rm -f $@.$$$$; false; } ; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

D_FILES=$(C_FILES:.c=.d)

ifneq ($(MAKECMDGOALS),clean)
include $(D_FILES)
endif

clean:
	rm -f *.o *.ll *.d bin/* ut/*.o ut/*.d ut/*.ll

# Fixes an issue where make thinks these .h files are dependencies that need
# to be built. Just include them as a noop in order to trick make.
/usr/include/%.h:
	@echo "No need to build $@"
