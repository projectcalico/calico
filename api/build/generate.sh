#!/bin/bash

# generate.sh orchestrates all API code generation. Called by the Makefile,
# which passes DOCKER_RUN, CALICO_BUILD, and PACKAGE_NAME via environment.
#
# Steps:
#   1. Run Go code generation inside go-build (build/codegen.sh)
#   2. Run prettier to normalize CRD YAML formatting
#   3. Apply CRD patches that work around code generator bugs

set -eo pipefail

: "${DOCKER_RUN:?DOCKER_RUN must be set}"
: "${CALICO_BUILD:?CALICO_BUILD must be set}"
: "${PACKAGE_NAME:?PACKAGE_NAME must be set}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Run all Go code generation inside the go-build container.
# DOCKER_RUN is a compound shell command (mkdir ... && docker run ...) so we
# need eval to interpret it.
eval "${DOCKER_RUN} -e PACKAGE_NAME=${PACKAGE_NAME} ${CALICO_BUILD} sh -c 'build/codegen.sh'"

# Run prettier to normalize CRD YAML indentation.
docker run --rm --user "$(id -u):$(id -g)" \
	-v "${REPO_ROOT}/config/crd/:/work/config/crd/" \
	tmknom/prettier --write --parser=yaml /work

# Patch in manual tweaks to the generated CRDs.
patch --no-backup-if-mismatch -p2 -d "${REPO_ROOT}" \
	< "${REPO_ROOT}/patches/0001-Add-nullable-to-IPAM-block-allocations-field.patch"
