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

OBJS:=$(shell ./list-objs)
C_FILES:=tc.c connect_balancer.c

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
