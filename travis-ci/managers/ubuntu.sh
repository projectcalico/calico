#!/bin/bash
set -e
set -x

RELEASE="bionic"

echo "deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse" >>/etc/apt/sources.list

apt-get update
apt-get -y build-dep libelf-dev
apt-get install -y libelf-dev pkg-config

source "$(dirname $0)/travis_wait.bash"

cd $REPO_ROOT

CFLAGS="-g -O2 -Werror -Wall -fsanitize=address,undefined"
mkdir build install
cc --version
make -j$((4*$(nproc))) CFLAGS="${CFLAGS}" -C ./src -B OBJDIR=../build
ldd build/libbpf.so
if ! ldd build/libbpf.so | grep -q libelf; then
    echo "FAIL: No reference to libelf.so in libbpf.so!"
    exit 1
fi
make -j$((4*$(nproc))) -C src OBJDIR=../build DESTDIR=../install install
rm -rf build install
