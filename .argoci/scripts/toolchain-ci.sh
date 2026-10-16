#!/bin/bash

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Helpers for .argoci/modules/10-toolchain.yaml: build a toolchain image whose
# tag is not published yet, push it to the CI registry, and hand it to the rest
# of the run. Source it; the step's `bash -e` stops on any failure here.

toolchain_dir() { echo "toolchain/images/$1"; }

# Prints build or published, and fails when the tag is published from other
# source: the change needs a new tag.
toolchain_state() { make -s -C "$(toolchain_dir "$1")" check-published; }

toolchain_ci_ref() { make -s -C "$(toolchain_dir "$1")" print-ci-ref; }

toolchain_login() {
  : "${GCR_SERVICE_ACCOUNT_KEY:?the google-service-account-for-gcr bundle is not mounted on this step}"
  printf '%s' "${GCR_SERVICE_ACCOUNT_KEY}" | docker login -u _json_key --password-stdin https://gcr.io
}

# toolchain_build <image> <arch>
toolchain_build() {
  local image=$1 arch=$2 state ref
  state=$(toolchain_state "${image}")
  echo "${image}: ${state}"
  if [ "${state}" = published ]; then return 0; fi
  ref=$(toolchain_ci_ref "${image}")
  toolchain_login
  # A rerun, or another PR with the same source, has already built it.
  if docker buildx imagetools inspect "${ref}-${arch}" >/dev/null 2>&1; then
    echo "${ref}-${arch} is already in the CI registry"
    return 0
  fi
  time make -C "$(toolchain_dir "${image}")" image test ci-push ARCH="${arch}"
}

# toolchain_manifest <image> <variable>: joins the arches built above and
# records <variable>=<ref> for `toolchain` to collect.
toolchain_manifest() {
  local image=$1 var=$2 state ref
  state=$(toolchain_state "${image}")
  if [ "${state}" = published ]; then return 0; fi
  ref=$(toolchain_ci_ref "${image}")
  toolchain_login
  if ! docker buildx imagetools inspect "${ref}" >/dev/null 2>&1; then
    make -C "$(toolchain_dir "${image}")" ci-manifest
  fi
  printf '%s=%s\n' "${var}" "${ref}" > "/tmp/${image}.env"
  artifact push workflow "/tmp/${image}.env" --destination "toolchain-env/${image}.env" --force
}

# toolchain_collect <env-file> <go-build-image-file>: the producer's outputs.
# An image this run built must have left its fragment, so a failed pull fails
# here rather than leaving every later step on an unpublished tag. An image it
# did not build is the published tag.
toolchain_collect() {
  local env_file=$1 image_file=$2 image go_build=""
  : > "${env_file}"
  for image in binfmt go-build rust-build; do
    if [ "$(toolchain_state "${image}")" = published ]; then continue; fi
    artifact pull workflow "toolchain-env/${image}.env" --destination "/tmp/${image}.env"
    cat "/tmp/${image}.env" >> "${env_file}"
  done
  go_build=$(sed -n 's/^CALICO_BUILD=//p' "${env_file}")
  if [ -z "${go_build}" ]; then
    go_build="calico/go-build:$(make -s -C "$(toolchain_dir go-build)" print-tag)"
  fi
  echo "go-build: ${go_build}"
  sed 's/^/  /' "${env_file}"
  echo "${go_build}" > "${image_file}"
}
