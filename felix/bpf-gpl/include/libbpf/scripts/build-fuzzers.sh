#!/bin/bash
set -eux

SANITIZER=${SANITIZER:-address}
flags="-O1 -fno-omit-frame-pointer -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize=fuzzer-no-link"

export CC=${CC:-clang}
export CFLAGS=${CFLAGS:-$flags}

export CXX=${CXX:-clang++}
export CXXFLAGS=${CXXFLAGS:-$flags}

cd "$(dirname -- "$0")/.."

export OUT=${OUT:-"$(pwd)/out"}
mkdir -p "$OUT"

export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

# libelf is compiled with _FORTIFY_SOURCE by default and it
# isn't compatible with MSan. It was borrowed
# from https://github.com/google/oss-fuzz/pull/7422
if [[ "$SANITIZER" == memory ]]; then
    CFLAGS+=" -U_FORTIFY_SOURCE"
    CXXFLAGS+=" -U_FORTIFY_SOURCE"
fi

# The alignment check is turned off by default on OSS-Fuzz/CFLite so it should be
# turned on explicitly there. It was borrowed from
# https://github.com/google/oss-fuzz/pull/7092
if [[ "$SANITIZER" == undefined ]]; then
    additional_ubsan_checks=alignment
    UBSAN_FLAGS="-fsanitize=$additional_ubsan_checks -fno-sanitize-recover=$additional_ubsan_checks"
    CFLAGS+=" $UBSAN_FLAGS"
    CXXFLAGS+=" $UBSAN_FLAGS"
fi

# Ideally libbelf should be built using release tarballs available
# at https://sourceware.org/elfutils/ftp/. Unfortunately sometimes they
# fail to compile (for example, elfutils-0.185 fails to compile with LDFLAGS enabled
# due to https://bugs.gentoo.org/794601) so let's just point the script to
# commits referring to versions of libelf that actually can be built
rm -rf elfutils
git clone https://sourceware.org/git/elfutils.git
(
cd elfutils
git checkout 67a187d4c1790058fc7fd218317851cb68bb087c
git log --oneline -1

# ASan isn't compatible with -Wl,--no-undefined: https://github.com/google/sanitizers/issues/380
sed -i 's/^\(NO_UNDEFINED=\).*/\1/' configure.ac

# ASan isn't compatible with -Wl,-z,defs either:
# https://clang.llvm.org/docs/AddressSanitizer.html#usage
sed -i 's/^\(ZDEFS_LDFLAGS=\).*/\1/' configure.ac

if [[ "$SANITIZER" == undefined ]]; then
    # That's basicaly what --enable-sanitize-undefined does to turn off unaligned access
    # elfutils heavily relies on on i386/x86_64 but without changing compiler flags along the way
    sed -i 's/\(check_undefined_val\)=[0-9]/\1=1/' configure.ac
fi

autoreconf -i -f
if ! ./configure --enable-maintainer-mode --disable-debuginfod --disable-libdebuginfod \
            --disable-demangler --without-bzlib --without-lzma --without-zstd \
	    CC="$CC" CFLAGS="-Wno-error $CFLAGS" CXX="$CXX" CXXFLAGS="-Wno-error $CXXFLAGS" LDFLAGS="$CFLAGS"; then
    cat config.log
    exit 1
fi

make -C config -j$(nproc) V=1
make -C lib -j$(nproc) V=1
make -C libelf -j$(nproc) V=1
)

make -C src BUILD_STATIC_ONLY=y V=1 clean
make -C src -j$(nproc) CFLAGS="-I$(pwd)/elfutils/libelf $CFLAGS" BUILD_STATIC_ONLY=y V=1

$CC $CFLAGS -Isrc -Iinclude -Iinclude/uapi -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64  -c fuzz/bpf-object-fuzzer.c -o bpf-object-fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE bpf-object-fuzzer.o src/libbpf.a "$(pwd)/elfutils/libelf/libelf.a" -l:libz.a -o "$OUT/bpf-object-fuzzer"

cp fuzz/bpf-object-fuzzer_seed_corpus.zip "$OUT"
