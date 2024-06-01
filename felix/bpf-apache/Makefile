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

# Workaround for Ubuntu placing "asm/types.h" in /usr/include/x86_64-linux-gnu
TRIPLET := $(shell gcc -dumpmachine)
CFLAGS += -I/usr/include/$(TRIPLET)

CC := clang-17
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
