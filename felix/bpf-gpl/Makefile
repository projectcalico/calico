# Project Calico BPF dataplane build scripts.
# Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# Disable implicit rules.
.SUFFIXES:

LIBBPF_DIR=libbpf
LIBBPF_FILE_CREATED=.libbpf-$(LIBBPF_VERSION)

# C flags for compiling BPF programs. "-target bpf" enables some workarounds
# for BPF programs and makes inline assembly aware of the BPF registers.
CFLAGS +=  \
	-Wall \
	-Werror \
	-fno-stack-protector \
	-Wno-address-of-packed-member \
	-O2 \
	-emit-llvm \
	-g

BPF_TARGET := bpf
ifeq ($(ARCH),s390x)
BPF_TARGET := bpfeb
endif
CFLAGS += -target $(BPF_TARGET)

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
	-I ./libbpf/src/ \
	-I ./libbpf/include/uapi

# Host architecture define — BPF compilation uses "-target bpf" which
# doesn't define the host arch, but glibc's gnu/stubs.h needs it to
# select the right stubs file.  Since BPF always compiles natively,
# derive this from the build host.
HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),x86_64)
CFLAGS += -D__x86_64__
else ifeq ($(HOST_ARCH),s390x)
CFLAGS += -D__s390x__
endif

# Set target-arch defines for BPF compilation.  ARCH is passed from
# felix/Makefile (defined in lib.Makefile as the target architecture).
ifeq ($(ARCH),amd64)
CFLAGS += -D__TARGET_ARCH_x86
else ifeq ($(ARCH),arm64)
CFLAGS += -D__TARGET_ARCH_arm64
else ifeq ($(ARCH),ppc64le)
CFLAGS += -D__TARGET_ARCH_powerpc -D__SANE_USERSPACE_TYPES__
else ifeq ($(ARCH),s390x)
CFLAGS += -D__TARGET_ARCH_s390
endif
CC := clang
LD := llc

UT_C_FILES:=$(shell find ut -name '*.c')
UT_OBJS:=$(UT_C_FILES:.c=.o) $(shell ./list-ut-objs)
UT_OBJS+=ut/ip_parse_test_v6.o
UT_OBJS+=ut/tcp_rst_v6.o

XDP_MAP_HEADERS := jump.h
COMMON_MAP_HEADERS := counters.h ifstate.h ringbuf.h profiling.h rule_counters.h qos.h ctlb_map.h $(XDP_MAP_HEADERS)
IP_MAP_HEADERS := arp.h conntrack_cleanup.h conntrack_types.h failsafe.h nat_types.h policy.h routes.h sendrecv.h
IPV4_MAP_HEADERS := $(IP_MAP_HEADERS) ip_v4_fragment.h
IPV6_MAP_HEADERS := $(IP_MAP_HEADERS)

MAP_OBJS := $(addprefix bin/, common_map_stub.o ipv4_map_stub.o ipv6_map_stub.o xdp_map_stub.o common_map_stub_ing.o)

# Map stub ojbs cannot have '-emit-llvm' in flags
MAP_CFLAGS := $(subst -emit-llvm,,$(CFLAGS))

# Generate _map_stub.c
define generate_stub
	echo '#include "bpf.h"' > $@; \
	for header in $^; do \
		echo "#include \"$${header}\"" >> $@; \
	done; \
	echo '' >> $@; \
	echo 'SEC("xdp")' >> $@; \
	echo 'int xdp_prog(struct xdp_md *ctx) { return XDP_PASS; }' >> $@;
endef

common_map_stub.c: $(COMMON_MAP_HEADERS)
	$(generate_stub)

ipv4_map_stub.c: $(IPV4_MAP_HEADERS)
	$(generate_stub)

ipv6_map_stub.c: $(IPV6_MAP_HEADERS)
	$(generate_stub)

xdp_map_stub.c: $(XDP_MAP_HEADERS)
	$(generate_stub)

bin/common_map_stub.o bin/ipv4_map_stub.o: bin/%.o: %.c %.d | bin
	$(CC) $(MAP_CFLAGS) -c $< -o $@

bin/common_map_stub_ing.o: bin/%.o: common_map_stub.c common_map_stub.d | bin
	$(CC) $(MAP_CFLAGS) -DCALI_COMPILE_FLAGS=2 -c $< -o $@

bin/ipv6_map_stub.o: bin/%.o: %.c %.d | bin
	$(CC) $(MAP_CFLAGS) -DIPVER6 -c $< -o $@

# CALI_COMPILE_FLAGS=64 is CALI_XDP_PROG
bin/xdp_map_stub.o: bin/%.o: %.c %.d | bin
	$(CC) $(MAP_CFLAGS) -DCALI_COMPILE_FLAGS=64 -c $< -o $@

OBJS:=$(shell ./list-objs)
OBJS+=bin/tc_preamble_ingress.o
OBJS+=bin/tc_preamble_egress.o
# Trace-printk-free preamble variants, loaded on nodes running with kernel
# lockdown=confidentiality (where ftrace is disabled and any program
# referencing bpf_trace_printk spams the kernel log on every load).
OBJS+=bin/tc_preamble_ingress_notrace.o
OBJS+=bin/tc_preamble_egress_notrace.o
OBJS+=bin/tcx_test.o
OBJS+=bin/xdp_preamble.o
OBJS+=bin/xdp_preamble_notrace.o
OBJS+=bin/policy_default_ingress.o
OBJS+=bin/policy_default_egress.o
OBJS+=$(MAP_OBJS)
C_FILES:=tc_preamble.c tc.c connect_balancer.c connect_balancer_v46.c connect_balancer_v6.c xdp_preamble.c xdp.c policy_default.c

all: $(OBJS)
ut-objs: $(UT_OBJS)
map-objs: $(MAP_OBJS)

libbpf: $(LIBBPF_FILE_CREATED)
# Clone libbpf at the pinned version in a single network round-trip.
# Using `--branch $(LIBBPF_VERSION)` with `--depth 1` avoids a separate
# `git fetch --tags` call, which was a flake source (GitHub occasionally
# returns HTTP 500 for tag listings).
#
# NO_LIBBPF_CLONE=1 turns the clone into a hard failure. CI sets this
# after restoring the libbpf tarball from GCS so that a missing marker
# surfaces as an error instead of silently re-cloning (which would
# negate the cache and restore the HTTP 500 flake risk).
$(LIBBPF_FILE_CREATED):
	@if [ -n "$$NO_LIBBPF_CLONE" ]; then \
		echo "ERROR: libbpf clone triggered but NO_LIBBPF_CLONE is set." >&2; \
		echo "       The GCS-cached libbpf tarball was not restored correctly." >&2; \
		exit 1; \
	fi
	rm -rf $(LIBBPF_DIR) .libbpf-*
	env -u GIT_DIR -u GIT_WORK_TREE git clone --depth 1 --branch $(LIBBPF_VERSION) https://github.com/libbpf/libbpf.git
	touch $(LIBBPF_FILE_CREATED)


COMPILE=$(CC) $(CFLAGS) `./calculate-flags $@` -c $< -o $@

UT_CFLAGS=\
	-D__BPFTOOL_LOADER__ \
	-DCALI_LOG_LEVEL=CALI_LOG_LEVEL_DEBUG \
	-DUNITTEST \
	-DCALI_LOG_PFX=UNITTEST \
	-I .

# Mini-UT programs that test one or two functions.  These are each in their own files.
ut/%.ll: ut/%.c ut/ut.h
	$(CC) $(UT_CFLAGS) $(CFLAGS) -c $< -o $@

ut/icmp6_port_unreachable.ll: CFLAGS += -DIPVER6

tc_preamble_ingress.ll: tc_preamble.c tc_preamble.d
	$(COMPILE)
tc_preamble_egress.ll: tc_preamble.c tc_preamble.d
	$(COMPILE)
tc_preamble_ingress_notrace.ll: tc_preamble.c tc_preamble.d
	$(COMPILE)
tc_preamble_ingress_notrace.ll: CFLAGS += -DCALI_NO_TRACE_PRINTK
tc_preamble_egress_notrace.ll: tc_preamble.c tc_preamble.d
	$(COMPILE)
tc_preamble_egress_notrace.ll: CFLAGS += -DCALI_NO_TRACE_PRINTK
tcx_test.ll: tcx_test.c tcx_test.d
	$(CC) $(CFLAGS) -c $< -o $@

xdp_preamble.ll: xdp_preamble.c xdp_preamble.d
	$(CC) $(CFLAGS) -DCALI_COMPILE_FLAGS=64 -c $< -o $@
xdp_preamble_notrace.ll: xdp_preamble.c xdp_preamble.d
	$(CC) $(CFLAGS) -DCALI_COMPILE_FLAGS=64 -DCALI_NO_TRACE_PRINTK -c $< -o $@

policy_default_ingress.ll: policy_default.c policy_default.d
	$(COMPILE)
policy_default_egress.ll: policy_default.c policy_default.d
	$(COMPILE)

# Production and UT versions of the main binaries.
# Combining the targets into one rule causes make to fail to rebuild the .ll files.  Not sure why.
to%_v6.ll: tc.c tc_v6.d calculate-flags
	$(COMPILE)
to%.ll: tc.c tc.d calculate-flags
	$(COMPILE)
from%.ll: tc.c tc.d calculate-flags
	$(COMPILE)
from%_v6.ll: tc.c tc_v6.d calculate-flags
	$(COMPILE)
test%.ll: tc.c tc.d calculate-flags
	$(COMPILE)
test%_v6.ll: tc.c tc_v6.d calculate-flags
	$(COMPILE)
xdp%.ll: xdp.c xdp.d calculate-flags
	$(COMPILE)
xdp%_v6.ll: xdp.c xdp_v6.d calculate-flags
	$(COMPILE)
test_xdp%.ll: xdp.c xdp.d calculate-flags
	$(COMPILE)
test_xdp%_v6.ll: xdp.c xdp_v6.d calculate-flags
	$(COMPILE)

tc.d: tc.c
	$(COMPILE_DEPS)
tc_v6.d: tc.c
	$(COMPILE_DEPS)
xdp.d: xdp.c
	$(COMPILE_DEPS)
xdp_v6.d: xdp.c
	$(COMPILE_DEPS)
connect_balancer.d: connect_balancer.c
	$(COMPILE_DEPS)
connect_balancer_v6.d: connect_balancer_v6.c
	$(COMPILE_DEPS)
connect_balancer_v46.d: connect_balancer_v46.c
	$(COMPILE_DEPS)
conntrack_cleanup.d: conntrack_cleanup.c
	$(COMPILE_DEPS)
conntrack_cleanup_v6.d: conntrack_cleanup.c
	$(COMPILE_DEPS)


# LLVM 21 added TrapUnreachable=true to the BPF backend (llvm/llvm-project#131731).
# This causes llc to emit a trap instruction (call to __bpf_trap kfunc) after
# every __builtin_unreachable().  Our bpf_exit() helper (bpf.h) uses inline asm
# to emit a BPF "exit" instruction followed by __builtin_unreachable() to tell
# the compiler the path is dead.  With TrapUnreachable, llc inserts a trap
# instruction after the exit; the kernel BPF verifier sees it as unreachable
# dead code ("unreachable insn N") and rejects every program.
#
# The flag -bpf-disable-trap-unreachable restores the LLVM 20 behaviour where
# __builtin_unreachable() generates no code.  It is cl::Hidden (internal to
# LLVM, not guaranteed stable across releases), but it was authored by a kernel
# BPF maintainer and is the only available workaround short of restructuring
# bpf_exit() or requiring kernel 6.16+ (which added the __bpf_trap kfunc).
#
# If a future LLVM release removes this flag, alternatives are:
#   - A stable clang flag like -ftrap-unreachable=none (proposed in
#     llvm/llvm-project#174894, not yet merged as of LLVM 22).
#   - Restructuring bpf_exit() to avoid inline asm "exit" + __builtin_unreachable().
#   - Requiring kernel 6.16+ and accepting the __bpf_trap kfunc calls.
LINK=$(LD) -march=$(BPF_TARGET) -filetype=obj -bpf-disable-trap-unreachable -o $@ $<
bin/tc_preamble_ingress.o: tc_preamble_ingress.ll | bin
	$(LINK)
bin/tc_preamble_egress.o: tc_preamble_egress.ll | bin
	$(LINK)
bin/tc_preamble_ingress_notrace.o: tc_preamble_ingress_notrace.ll | bin
	$(LINK)
bin/tc_preamble_egress_notrace.o: tc_preamble_egress_notrace.ll | bin
	$(LINK)
bin/tcx_test.o: tcx_test.ll | bin
	$(LINK)
bin/xdp_preamble.o: xdp_preamble.ll | bin
	$(LINK)
bin/xdp_preamble_notrace.o: xdp_preamble_notrace.ll | bin
	$(LINK)
bin/policy_default_ingress.o: policy_default_ingress.ll | bin
	$(LINK)
bin/policy_default_egress.o: policy_default_egress.ll | bin
	$(LINK)
bin/to%.o: to%.ll | bin
	$(LINK)
bin/from%.o: from%.ll | bin
	$(LINK)
bin/test%.o: test%.ll | bin
	$(LINK)
bin/xdp%.o: xdp%.ll | bin
	$(LINK)
ut/%.o: ut/%.ll
	$(LINK)
ut/ip_parse_test_v6.ll: ut/ip_parse_test.c
	$(CC) $(UT_CFLAGS) $(CFLAGS) -DIPVER6 -c $< -o $@
ut/ip_parse_test_v6.o: ut/ip_parse_test_v6.ll
	$(LINK)
ut/tcp_rst_v6.ll: ut/tcp_rst.c
	$(CC) $(UT_CFLAGS) $(CFLAGS) -DIPVER6 -c $< -o $@
ut/tcp_rst_v6.o: ut/tcp_rst_v6.ll
	$(LINK)

%_v4.ll: %.c %.d calculate-flags
	$(COMPILE)
%_no_log_v4.ll: %.c %.d calculate-flags
	$(COMPILE)
%_debug_v4.ll: %.c %.d calculate-flags
	$(COMPILE)

%_v4.ll: %_v4.c %_v4.d calculate-flags
	$(COMPILE)
%_no_log_v4.ll: %_v4.c %_v4.d calculate-flags
	$(COMPILE)
%_debug_v4.ll: %_v4.c %_v4.d calculate-flags
	$(COMPILE)

%_v46.ll: %_v46.c %_v46.d calculate-flags
	$(COMPILE)
%_no_log_v46.ll: %_v46.c %_v46.d calculate-flags
	$(COMPILE)
%_debug_v46.ll: %_v46.c %_v46.d calculate-flags
	$(COMPILE)

%_v6.ll: %_v6.c %_v6.d calculate-flags
	$(COMPILE)
%_no_log_v6.ll: %_v6.c %_v6.d calculate-flags
	$(COMPILE)
%_debug_v6.ll: %_v6.c %_v6.d calculate-flags
	$(COMPILE)

%_v6.ll: %.c %_v6.d calculate-flags
	$(COMPILE)
%_no_log_v6.ll: %.c %_v6.d calculate-flags
	$(COMPILE)
%_debug_v6.ll: %.c %_v6.d calculate-flags
	$(COMPILE)

%_no_log.ll: %.c %.d calculate-flags
	$(COMPILE)
%_debug.ll: %.c %.d calculate-flags
	$(COMPILE)

bin/%_v4.o: %_v4.ll | bin
	$(LINK)
bin/%_v46.o: %_v46.ll | bin
	$(LINK)
bin/%_v6.o: %_v6.ll | bin
	$(LINK)
bin/%.o: %.ll | bin
	$(LINK)

bin:
	mkdir -p bin

%.d: %.c
	$(COMPILE_DEPS)
%_v6.d: CFLAGS+=-DIPVER6
%_v6.d: %_v6.c
	$(COMPILE_DEPS)
%_v6.d: %.c
	$(COMPILE_DEPS)

.PRECIOUS: %.d %_v6.d

COMPILE_DEPS=set -e; rm -f $@; \
		$(CC) -MP -M $(CFLAGS) $< > $@.$$$$ || { rm -f $@.$$$$; false; } ; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

ifneq ($(MAKECMDGOALS),clean)
  ifneq ($(MAKECMDGOALS), libbpf)
    include $(wildcard *.d)
  endif
endif

clean:
	rm -f *.o *.ll *.d bin/* ut/*.o ut/*.d ut/*.ll *_map_stub.c

# TODO: remove these catch-all rules once all .d files have been regenerated
# with -MP (above).  They handle stale .d files that predate the -MP flag.
/usr/include/%.h:
	@echo "No need to build $@"
