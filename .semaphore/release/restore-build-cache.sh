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

# Restore the Go build and module caches that CI on a build-v* branch pushed
# to this workflow's artifacts, so that the release build starts warm.
#
# The CI epilogue (semaphore.yml.d/02-global_job_config.yml) pushes one tarball
# per BUILD_CACHE_GROUP to the workflow artifact go-cache/, containing $HOME/go
# (module cache) and $HOME/<repo>/.go-pkg-cache (build cache). Workflow
# artifacts are only written by jobs in the same workflow, so the caches come
# from CI for the commit being released and never from another branch or a PR.
# The caller must export LOCAL_GO_PKG_CACHE=$HOME/<repo>/.go-pkg-cache so the
# build mounts the restored build cache.
#
# Best effort: any failure leaves the build to run with a cold cache.
#
# Usage: restore-build-cache.sh

set -uo pipefail

repo_dir=${SEMAPHORE_GIT_DIR:-calico}
# Stop restoring groups once free disk drops below this; the release build
# itself needs plenty of room for images.
min_free_gb=${RELEASE_CACHE_MIN_FREE_GB:-60}

command -v zstd >/dev/null || sudo apt-get install -y zstd || exit 0

download_dir=$(mktemp -d)
trap 'rm -rf "$download_dir"' EXIT
if ! artifact pull workflow go-cache -d "$download_dir/go-cache"; then
  echo "[cache] No Go caches in this workflow's artifacts, building cold"
  exit 0
fi

for tarball in "$download_dir"/go-cache/build-cache-*.tar.zstd; do
  [[ -f $tarball ]] || continue
  group=$(basename "$tarball" .tar.zstd)
  group=${group#build-cache-}
  free_gb=$(df --output=avail -BG "$HOME" | tail -1 | tr -dc '0-9')
  if (( free_gb < min_free_gb )); then
    echo "[cache] Only ${free_gb}GB free, not restoring any more groups"
    break
  fi
  echo "[cache] Restoring build cache group ${group} (${free_gb}GB free)"
  start=$SECONDS
  # Extract only the two cache directories, so a bad tarball can't write
  # anywhere else under $HOME (dotfiles, the checkout itself).
  #
  # Groups overlap, so each one is merged over the ones before it. Both caches
  # are content-addressed (build cache by action hash, module cache by
  # module@version), so a file that already exists holds the same content and
  # is skipped. Skipping also avoids failing on the read-only module cache, and
  # leaves existing directories (including $HOME) untouched.
  if zstd -dc "$tarball" |
    tar -x -C "$HOME" --no-same-owner --skip-old-files -- go/pkg/mod "${repo_dir}/.go-pkg-cache"; then
    echo "[cache] Restored ${group} in $((SECONDS - start))s"
  else
    echo "[cache] Failed to restore ${group}, continuing"
  fi
  rm -f "$tarball"
done

# Check the restored modules against go.sum; drop them all if anything differs.
# GOTOOLCHAIN=local so we never run a toolchain that came out of the cache.
if [[ -d $HOME/go/pkg/mod ]]; then
  if ! (cd "$HOME/${repo_dir}" && GOMODCACHE=$HOME/go/pkg/mod GOFLAGS='' GOTOOLCHAIN=local go mod verify); then
    echo "[cache] Module cache failed verification, discarding it"
    chmod -R u+w "$HOME/go/pkg/mod"
    rm -rf "$HOME/go/pkg/mod"
  fi
fi

du -sh "$HOME/go/pkg/mod" "$HOME/${repo_dir}/.go-pkg-cache" 2>/dev/null || true
exit 0
