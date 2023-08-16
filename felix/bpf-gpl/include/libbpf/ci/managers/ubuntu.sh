#!/bin/bash
set -eux

RELEASE="focal"

apt-get update
apt-get install -y pkg-config

source "$(dirname $0)/travis_wait.bash"

cd $REPO_ROOT

EXTRA_CFLAGS="-Werror -Wall -fsanitize=address,undefined"
EXTRA_LDFLAGS="-Werror -Wall -fsanitize=address,undefined"
mkdir build install
cc --version
make -j$((4*$(nproc))) EXTRA_CFLAGS="${EXTRA_CFLAGS}" EXTRA_LDFLAGS="${EXTRA_LDFLAGS}" -C ./src -B OBJDIR=../build
ldd build/libbpf.so
if ! ldd build/libbpf.so | grep -q libelf; then
    echo "FAIL: No reference to libelf.so in libbpf.so!"
    exit 1
fi
make -j$((4*$(nproc))) -C src OBJDIR=../build DESTDIR=../install install
EXTRA_CFLAGS=${EXTRA_CFLAGS} EXTRA_LDFLAGS=${EXTRA_LDFLAGS} $(dirname $0)/test_compile.sh
