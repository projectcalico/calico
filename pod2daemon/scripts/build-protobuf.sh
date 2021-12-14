#!/bin/bash
## Execute this script from the base of the workspace.

set -o errexit

if [ -z "${ROOT}" ]; then
  ROOT=$(pwd)
fi
PROTODIRS=$(ls "${ROOT}/protos" | grep -v BUILD)

for f in ${PROTODIR}; do
  bazel build //protos/${f}:protolib
done

genfiles=$(bazel info bazel-genfiles)

files=$(find -L ${genfiles} -name "*.pb.go")

echo ${files}
for src in ${files}; do
  dst=${src##${genfiles}/}
  echo "src $src, dst $dst"
  if [ -d "$(dirname ${dst})" ]; then
    install -m 04500 ${src} ${dst}
  fi
done
