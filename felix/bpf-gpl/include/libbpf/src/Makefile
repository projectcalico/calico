# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
endif

LIBBPF_MAJOR_VERSION := 1
LIBBPF_MINOR_VERSION := 5
LIBBPF_PATCH_VERSION := 0
LIBBPF_VERSION := $(LIBBPF_MAJOR_VERSION).$(LIBBPF_MINOR_VERSION).$(LIBBPF_PATCH_VERSION)
LIBBPF_MAJMIN_VERSION := $(LIBBPF_MAJOR_VERSION).$(LIBBPF_MINOR_VERSION).0
LIBBPF_MAP_VERSION := $(shell grep -oE '^LIBBPF_([0-9.]+)' libbpf.map | sort -rV | head -n1 | cut -d'_' -f2)
ifneq ($(LIBBPF_MAJMIN_VERSION), $(LIBBPF_MAP_VERSION))
$(error Libbpf release ($(LIBBPF_VERSION)) and map ($(LIBBPF_MAP_VERSION)) versions are out of sync!)
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

TOPDIR = ..

INCLUDES := -I. -I$(TOPDIR)/include -I$(TOPDIR)/include/uapi
ALL_CFLAGS := $(INCLUDES)

SHARED_CFLAGS += -fPIC -fvisibility=hidden -DSHARED

CFLAGS ?= -g -O2 -Werror -Wall -std=gnu89
ALL_CFLAGS += $(CFLAGS) 						\
	      -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64		\
	      -Wno-unknown-warning-option -Wno-format-overflow		\
	      $(EXTRA_CFLAGS)
ALL_LDFLAGS += $(LDFLAGS) $(EXTRA_LDFLAGS)

ifdef NO_PKG_CONFIG
	ALL_LDFLAGS += -lelf -lz
else
	PKG_CONFIG ?= pkg-config
	ALL_CFLAGS += $(shell $(PKG_CONFIG) --cflags libelf zlib)
	ALL_LDFLAGS += $(shell $(PKG_CONFIG) --libs libelf zlib)
endif

OBJDIR ?= .
SHARED_OBJDIR := $(OBJDIR)/sharedobjs
STATIC_OBJDIR := $(OBJDIR)/staticobjs
OBJS := bpf.o btf.o libbpf.o libbpf_errno.o netlink.o \
	nlattr.o str_error.o libbpf_probes.o bpf_prog_linfo.o \
	btf_dump.o hashmap.o ringbuf.o strset.o linker.o gen_loader.o \
	relo_core.o usdt.o zip.o elf.o features.o
SHARED_OBJS := $(addprefix $(SHARED_OBJDIR)/,$(OBJS))
STATIC_OBJS := $(addprefix $(STATIC_OBJDIR)/,$(OBJS))

STATIC_LIBS := $(OBJDIR)/libbpf.a
ifndef BUILD_STATIC_ONLY
	SHARED_LIBS := $(OBJDIR)/libbpf.so \
		       $(OBJDIR)/libbpf.so.$(LIBBPF_MAJOR_VERSION) \
		       $(OBJDIR)/libbpf.so.$(LIBBPF_VERSION)
	VERSION_SCRIPT := libbpf.map
endif

HEADERS := bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h \
	   bpf_helpers.h bpf_helper_defs.h bpf_tracing.h \
	   bpf_endian.h bpf_core_read.h skel_internal.h libbpf_version.h \
	   usdt.bpf.h
UAPI_HEADERS := $(addprefix $(TOPDIR)/include/uapi/linux/,\
			    bpf.h bpf_common.h btf.h)

PC_FILE := $(OBJDIR)/libbpf.pc

INSTALL = install

DESTDIR ?=

HOSTARCH = $(firstword $(subst -, ,$(shell $(CC) -dumpmachine)))
ifeq ($(filter-out %64 %64be %64eb %64le %64el s390x, $(HOSTARCH)),)
	LIBSUBDIR := lib64
else
	LIBSUBDIR := lib
endif

# By default let the pc file itself use ${prefix} in includedir/libdir so that
# the prefix can be overridden at runtime (eg: --define-prefix)
ifndef LIBDIR
	LIBDIR_PC := $$\{prefix\}/$(LIBSUBDIR)
else
	LIBDIR_PC := $(LIBDIR)
endif
PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/$(LIBSUBDIR)
INCLUDEDIR ?= $(PREFIX)/include
UAPIDIR ?= $(PREFIX)/include

TAGS_PROG := $(if $(shell which etags 2>/dev/null),etags,ctags)

all: $(STATIC_LIBS) $(SHARED_LIBS) $(PC_FILE)

$(OBJDIR)/libbpf.a: $(STATIC_OBJS)
	$(call msg,AR,$@)
	$(Q)$(AR) rcs $@ $^

$(OBJDIR)/libbpf.so: $(OBJDIR)/libbpf.so.$(LIBBPF_MAJOR_VERSION)
	$(Q)ln -sf $(^F) $@

$(OBJDIR)/libbpf.so.$(LIBBPF_MAJOR_VERSION): $(OBJDIR)/libbpf.so.$(LIBBPF_VERSION)
	$(Q)ln -sf $(^F) $@

$(OBJDIR)/libbpf.so.$(LIBBPF_VERSION): $(SHARED_OBJS)
	$(call msg,CC,$@)
	$(Q)$(CC) -shared -Wl,--version-script=$(VERSION_SCRIPT) \
		  -Wl,-soname,libbpf.so.$(LIBBPF_MAJOR_VERSION) \
		  $^ $(ALL_LDFLAGS) -o $@

$(OBJDIR)/libbpf.pc: force
	$(Q)sed -e "s|@PREFIX@|$(PREFIX)|" \
		-e "s|@LIBDIR@|$(LIBDIR_PC)|" \
		-e "s|@VERSION@|$(LIBBPF_VERSION)|" \
		< libbpf.pc.template > $@

$(STATIC_OBJDIR) $(SHARED_OBJDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(STATIC_OBJDIR)/%.o: %.c | $(STATIC_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(CPPFLAGS) -c $< -o $@

$(SHARED_OBJDIR)/%.o: %.c | $(SHARED_OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(ALL_CFLAGS) $(SHARED_CFLAGS) $(CPPFLAGS) -c $< -o $@

define do_install
	$(call msg,INSTALL,$1)
	$(Q)if [ ! -d '$(DESTDIR)$2' ]; then		\
		$(INSTALL) -d -m 755 '$(DESTDIR)$2';	\
	fi;
	$(Q)$(INSTALL) $(if $3,-m $3,) $1 '$(DESTDIR)$2'
endef

# Preserve symlinks at installation.
define do_s_install
	$(call msg,INSTALL,$1)
	$(Q)if [ ! -d '$(DESTDIR)$2' ]; then		\
		$(INSTALL) -d -m 755 '$(DESTDIR)$2';	\
	fi;
	$(Q)cp -fR $1 '$(DESTDIR)$2'
endef

install: all install_headers install_pkgconfig
	$(call do_s_install,$(STATIC_LIBS) $(SHARED_LIBS),$(LIBDIR))

install_headers:
	$(call do_install,$(HEADERS),$(INCLUDEDIR)/bpf,644)

# UAPI headers can be installed by a different package so they're not installed
# in by install rule.
install_uapi_headers:
	$(call do_install,$(UAPI_HEADERS),$(UAPIDIR)/linux,644)

install_pkgconfig: $(PC_FILE)
	$(call do_install,$(PC_FILE),$(LIBDIR)/pkgconfig,644)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf *.o *.a *.so *.so.* *.pc $(SHARED_OBJDIR) $(STATIC_OBJDIR)

.PHONY: cscope tags force
cscope:
	$(call msg,CSCOPE)
	$(Q)ls *.c *.h > cscope.files
	$(Q)cscope -b -q -f cscope.out

tags:
	$(call msg,CTAGS)
	$(Q)rm -f TAGS tags
	$(Q)ls *.c *.h | xargs $(TAGS_PROG) -a

force:
