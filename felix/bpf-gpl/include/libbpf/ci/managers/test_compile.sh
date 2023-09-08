#!/bin/bash
set -euox pipefail

EXTRA_CFLAGS=${EXTRA_CFLAGS:-}
EXTRA_LDFLAGS=${EXTRA_LDFLAGS:-}

cat << EOF > main.c
#include <bpf/libbpf.h>
int main() {
  return bpf_object__open(0) < 0;
}
EOF

# static linking
${CC:-cc} ${EXTRA_CFLAGS} ${EXTRA_LDFLAGS} -o main -I./include/uapi -I./install/usr/include main.c ./build/libbpf.a -lelf -lz
