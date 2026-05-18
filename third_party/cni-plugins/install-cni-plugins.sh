#!/bin/sh
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Copies upstream CNI plugin binaries from /plugins/ into the staging dir
# (default /stage/). The calico-node install-cni init container mounts the
# same staging dir at /opt/cni/bin so the existing install code can pick the
# binaries up and copy them onto the host.

set -eu

STAGE_DIR="${STAGE_DIR:-/stage}"

mkdir -p "${STAGE_DIR}"
cp -a /plugins/. "${STAGE_DIR}/"

echo "Staged CNI plugins to ${STAGE_DIR}:"
ls -l "${STAGE_DIR}"
