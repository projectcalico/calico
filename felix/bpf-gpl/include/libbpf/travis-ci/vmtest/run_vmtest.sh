#!/bin/bash

set -eu

source $(cd $(dirname $0) && pwd)/helpers.sh

VMTEST_SETUPCMD="PROJECT_NAME=${PROJECT_NAME} ./${PROJECT_NAME}/travis-ci/vmtest/run_selftests.sh"

echo "KERNEL: $KERNEL"
echo

# Build latest pahole
${VMTEST_ROOT}/build_pahole.sh travis-ci/vmtest/pahole

travis_fold start install_clang "Installing Clang/LLVM"

wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo add-apt-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal main"
sudo apt-get update
sudo apt-get install --allow-downgrades -y libc6=2.31-0ubuntu9.2
sudo aptitude install -y g++ libelf-dev
sudo aptitude install -y clang-13 lld-13 llvm-13

travis_fold end install_clang

# Build selftests (and latest kernel, if necessary)
KERNEL="${KERNEL}" ${VMTEST_ROOT}/prepare_selftests.sh travis-ci/vmtest/bpf-next

# Escape whitespace characters.
setup_cmd=$(sed 's/\([[:space:]]\)/\\\1/g' <<< "${VMTEST_SETUPCMD}")

sudo adduser "${USER}" kvm

if [[ "${KERNEL}" = 'LATEST' ]]; then
  sudo -E sudo -E -u "${USER}" "${VMTEST_ROOT}/run.sh" -b travis-ci/vmtest/bpf-next -o -d ~ -s "${setup_cmd}" ~/root.img;
else
  sudo -E sudo -E -u "${USER}" "${VMTEST_ROOT}/run.sh" -k "${KERNEL}*" -o -d ~ -s "${setup_cmd}" ~/root.img;
fi
