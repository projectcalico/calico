#!/usr/bin/env bash

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Tests for hack/check-image-arch.sh.
# Builds tiny arm64 images, one carrying an amd64 entrypoint binary (the
# projectcalico/calico#13183 failure) and one carrying an arm64 binary, and
# asserts the checker fails on the former and passes on the latter.
# Run with:  bash hack/check-image-arch_test.sh
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="${SCRIPT_DIR}/check-image-arch.sh"

if ! command -v docker >/dev/null 2>&1; then
	echo "docker not available; skipping check-image-arch tests"
	exit 0
fi

WORK="$(mktemp -d)"
IMAGES=()
trap 'docker rmi -f "${IMAGES[@]}" >/dev/null 2>&1 || true; rm -rf "${WORK}"' EXIT

PASS=0
FAIL=0

# assert_exit EXPECTED_CODE MESSAGE -- CMD...
assert_exit() {
	local want="$1" msg="$2"; shift 3
	local got=0
	"$@" >/dev/null 2>&1 || got=$?
	if [[ "${got}" == "${want}" ]]; then
		echo "ok   - ${msg}"
		PASS=$((PASS + 1))
	else
		echo "FAIL - ${msg} (want exit ${want}, got ${got})"
		FAIL=$((FAIL + 1))
	fi
}

# Write a minimal ELF header for the given e_machine value (EM_X86_64=62,
# EM_AARCH64=183), little-endian, enough for the checker to read.
write_elf_stub() {
	local machine="$1" path="$2"
	python3 - "${machine}" "${path}" <<'PY'
import sys
machine = int(sys.argv[1])
b = bytearray(64)
b[0:4] = b"\x7fELF"
b[4] = 2            # EI_CLASS = ELFCLASS64
b[5] = 1            # EI_DATA  = ELFDATA2LSB
b[6] = 1            # EI_VERSION
b[18] = machine & 0xFF
b[19] = (machine >> 8) & 0xFF
open(sys.argv[2], "wb").write(bytes(b))
PY
}

# build_image TAG ELF_MACHINE -- an arm64 image whose entrypoint binary has the
# given ELF machine. A wrong-arch binary (amd64 in an arm64 image) reproduces
# the bug; a matching one is the fixed case.
build_image() {
	local tag="$1" machine="$2"
	write_elf_stub "${machine}" "${WORK}/entry"
	printf 'FROM scratch\nCOPY entry /entry\nENTRYPOINT ["/entry"]\n' >"${WORK}/Dockerfile"
	docker build -q --platform=linux/arm64 -t "${tag}" "${WORK}" >/dev/null
	IMAGES+=("${tag}")
}

# build_unverifiable_image TAG DOCKERFILE_BODY -- an arm64 image the checker
# cannot verify (non-ELF entrypoint, or no entrypoint/command at all).
build_unverifiable_image() {
	local tag="$1" body="$2"
	echo "not an elf binary" >"${WORK}/entry"
	printf '%b' "${body}" >"${WORK}/Dockerfile"
	docker build -q --platform=linux/arm64 -t "${tag}" "${WORK}" >/dev/null
	IMAGES+=("${tag}")
}

build_image check-image-arch-test:wrong 62  # amd64 binary in an arm64 image
build_image check-image-arch-test:right 183 # arm64 binary in an arm64 image
build_unverifiable_image check-image-arch-test:nonelf 'FROM scratch\nCOPY entry /entry\nENTRYPOINT ["/entry"]\n'
build_unverifiable_image check-image-arch-test:noentry 'FROM scratch\nCOPY entry /entry\n'

assert_exit 1 "arm64 image with an amd64 binary is rejected" \
	-- "${CHECK}" arm64 check-image-arch-test:wrong
assert_exit 0 "arm64 image with an arm64 binary is accepted" \
	-- "${CHECK}" arm64 check-image-arch-test:right
assert_exit 1 "non-ELF entrypoint is rejected (cannot be verified)" \
	-- "${CHECK}" arm64 check-image-arch-test:nonelf
assert_exit 1 "image with no entrypoint or command is rejected" \
	-- "${CHECK}" arm64 check-image-arch-test:noentry

echo "----"
echo "PASS=${PASS} FAIL=${FAIL}"
[[ "${FAIL}" == 0 ]]
