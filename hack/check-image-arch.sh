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

# check-image-arch.sh EXPECTED_ARCH IMAGE [IMAGE...]
#
# Verify that each image is really built for EXPECTED_ARCH: both the image
# config's Architecture and the ELF machine of its entrypoint binary must
# match. Guards against multi-arch builds that advertise an arch but ship a
# wrong-arch binary, which fails at runtime with:
#   exec /usr/bin/<binary>: Exec format error
# (see https://github.com/projectcalico/calico/issues/13183).
#
# The binary is inspected, never executed, so this is safe for distroless and
# scratch-based images. Exits non-zero if any image has a wrong-arch binary or
# cannot be verified (no entrypoint/command, or a non-ELF entrypoint).
set -euo pipefail

if [ "$#" -lt 2 ]; then
	echo "usage: $0 EXPECTED_ARCH IMAGE [IMAGE...]" >&2
	exit 2
fi

expected=$1
shift

# ELF e_machine (EM_*) -> docker/GOARCH name, for the arches Calico builds.
em_to_arch() {
	case "$1" in
	62)  echo amd64 ;;   # EM_X86_64
	183) echo arm64 ;;   # EM_AARCH64
	21)  echo ppc64le ;; # EM_PPC64
	22)  echo s390x ;;   # EM_S390
	243) echo riscv64 ;; # EM_RISCV
	*)   echo "em:$1" ;;
	esac
}

# Read the ELF e_machine field, honoring the header's endianness (EI_DATA),
# so big-endian targets (s390x) are read correctly too.
elf_arch() {
	local f=$1 magic data b18 b19
	magic=$(dd if="$f" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
	[ "$magic" = "7f454c46" ] || { echo notelf; return; }
	data=$(dd if="$f" bs=1 skip=5 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
	b18=$(dd if="$f" bs=1 skip=18 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
	b19=$(dd if="$f" bs=1 skip=19 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
	if [ "$data" = 2 ]; then # ELFDATA2MSB (big-endian)
		em_to_arch $((b18 * 256 + b19))
	else # ELFDATA2LSB (little-endian)
		em_to_arch $((b18 + b19 * 256))
	fi
}

rc=0
for img in "$@"; do
	cfg_arch=$(docker inspect --format '{{.Architecture}}' "$img")
	if [ "$cfg_arch" != "$expected" ]; then
		echo "FAIL  $img  config.Architecture=$cfg_arch  expected=$expected"
		rc=1
		continue
	fi

	# The binary to check is the entrypoint, falling back to the command. As a
	# build gate, an image we were asked to check but cannot verify is a failure,
	# not a pass -- otherwise a wrong-arch image could slip through unchecked.
	entrypoint=$(docker inspect --format '{{if .Config.Entrypoint}}{{index .Config.Entrypoint 0}}{{else if .Config.Cmd}}{{index .Config.Cmd 0}}{{end}}' "$img")
	if [ -z "$entrypoint" ]; then
		echo "FAIL  $img  (no entrypoint or command to inspect; cannot verify arch)"
		rc=1
		continue
	fi

	cid=$(docker create "$img")
	tmp=$(mktemp)
	if ! docker cp "$cid:$entrypoint" "$tmp" 2>/dev/null; then
		echo "FAIL  $img  (entrypoint $entrypoint is not a copyable file; cannot verify arch)"
		rc=1
		docker rm "$cid" >/dev/null
		rm -f "$tmp"
		continue
	fi
	docker rm "$cid" >/dev/null

	bin_arch=$(elf_arch "$tmp")
	rm -f "$tmp"

	if [ "$bin_arch" = notelf ]; then
		echo "FAIL  $img  (entrypoint $entrypoint is not an ELF binary; cannot verify arch)"
		rc=1
		continue
	fi

	if [ "$bin_arch" = "$expected" ]; then
		echo "OK    $img  arch=$expected  ($entrypoint)"
	else
		echo "FAIL  $img  binary=$bin_arch  expected=$expected  ($entrypoint)  <-- wrong-arch binary"
		rc=1
	fi
done

exit $rc
