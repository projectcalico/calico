# Project Calico BPF dataplane build scripts.
# Copyright (c) 2020 Tigera, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Disable implicit rules.
.SUFFIXES:

# We want to build against the up-to-date kernel headers from the linux-headers package.
# However, if we just put them on the include path, we pull in transient dependencies
# that can only really be built with the kernel build system.  For now, just force-include
# exactly the files that we need and let the rest be pulled from the system's standard include
# directories.
LINUX_COMMON=$(wildcard /usr/src/linux-headers-*-common)
LINUX_AMD64=$(wildcard /usr/src/linux-headers-*-amd64)

CFLAGS +=  \
	-x c \
	-D__KERNEL__ \
	-D__ASM_SYSREG_H \
	-D__LINUX_BPF_H__ \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wunused \
	-Wall \
	-Werror \
	-fno-stack-protector \
	-O2 \
	-emit-llvm \
	--include=$(LINUX_COMMON)/include/uapi/linux/bpf.h \
	--include=$(LINUX_AMD64)/include/generated/uapi/linux/version.h

CC := clang
LD := llc

UT_C_FILES:=$(shell find ut -name '*.c')
UT_OBJS:=$(UT_C_FILES:.c=.o) $(shell ./list-ut-objs)

OBJS:=$(shell ./list-objs)
C_FILES:=tc.c connect_balancer.c

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
	-DCALI_VXLAN_PORT=5665 \
	-DCALI_NAT_TUNNEL_MTU=700 \
	-DCALI_HOST_IP=0x01000a0a \
	-DUNITTEST \
	-DCALI_LOG_PFX=UNITTEST \
	-I .

# Mini-UT programs that test one or two functions.  These are each in their own files.
ut/%.ll: ut/%.c ut/ut.h tc.c tc.d
	$(CC) $(CFLAGS) $(UT_CFLAGS) -c $< -o $@

# Production and UT versions of the main binaries.
# Combining the targets into one rule causes make to fail to rebuild the .ll files.  Not sure why.
to%.ll: tc.c tc.d calculate-flags
	$(COMPILE)
from%.ll: tc.c tc.d calculate-flags
	$(COMPILE)
test%.ll: tc.c tc.d calculate-flags
	$(COMPILE)

LINK=$(LD) -march=bpf -filetype=obj -o $@ $<
bin/to%.o: to%.ll | bin
	$(LINK)
bin/from%.o: from%.ll | bin
	$(LINK)
bin/test%.o: test%.ll | bin
	$(LINK)
bin/connect_time_%v4.o: connect_time_%v4.ll | bin
	$(LINK)
bin/connect_time_%v6.o: connect_time_%v6.ll | bin
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
include $(D_FILES)

clean:
	rm -f *.o *.ll *.d bin/* ut/*.o ut/*.d ut/*.ll
