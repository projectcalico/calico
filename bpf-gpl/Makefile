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

UT_C_FILES:=$(shell find ut -name '*.c')
UT_OBJS:=$(UT_C_FILES:.c=.o) $(shell ./list-ut-objs)

OBJS:=$(shell ./list-objs)
C_FILES:=tc.c connect_balancer.c

all: $(OBJS) $(UT_OBJS)

connect_time%.ll: connect_balancer.c connect_balancer.d
	$(CC) $(CFLAGS) `./calculate-flags $@` -c $< -o $@

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
%.ll: tc.c tc.d
	$(CC) $(CFLAGS) `./calculate-flags $@` -c $< -o $@

LINK=$(LD) -march=bpf -filetype=obj -o $@ $<
bin/%.o: %.ll | bin
	$(LINK)
ut/%.o: ut/%.ll
	$(LINK)

bin:
	mkdir -p bin

.PRECIOUS: %.d

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -M $(CFLAGS) $< > $@.$$$$ || { rm -f $@.$$$$; false; } ; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

D_FILES=$(C_FILES:.c=.d)
include $(D_FILES)

clean:
	rm -f *.o *.ll *.d bin/* ut/*.o ut/*.d ut/*.ll
