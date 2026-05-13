# Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Disable implicit rules.
.SUFFIXES:

CFLAGS +=  \
	-x c \
	-D__KERNEL__ \
	-D__ASM_SYSREG_H \
	-Wunused \
	-Wall \
	-Werror \
	-fno-stack-protector \
	-O2 \
	-target bpf \
	-emit-llvm \
	-g

# Host architecture define — BPF compilation uses "-target bpf" which
# doesn't define the host arch, but glibc's gnu/stubs.h needs it to
# select the right stubs file.  Since BPF always compiles natively,
# derive this from the build host.
HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),x86_64)
CFLAGS += -D__x86_64__
endif

CC := clang
LD := llc

C_FILES:=filter.c redir.c sockops.c
OBJS:=$(addprefix bin/,$(C_FILES:.c=.o))

all: $(OBJS)

%.ll: %.c %.d
	$(CC) $(CFLAGS) -c $< -o $@

bin/%.o: %.ll | bin
	$(LD) -march=bpf -filetype=obj -o $@ $<

bin:
	mkdir -p bin

.PRECIOUS: %.d

%.d: %.c
	@set -e; rm -f $@; \
		$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

D_FILES:=$(C_FILES:.c=.d)

ifneq ($(MAKECMDGOALS),clean)
include $(D_FILES)
endif

clean:
	rm -f *.o *.ll *.d bin/*
