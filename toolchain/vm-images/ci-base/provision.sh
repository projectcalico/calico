#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Provisioner for the ci-base VM image -- any CI job needing docker/go/kubectl on a
# GCE VM. Runs once as a throwaway builder's startup-script; its disk becomes the
# image. Publishes /var/run/provision-done when finished.
set -xeuo pipefail
export DEBIAN_FRONTEND=noninteractive

# Injected by build-image.sh. Required, not defaulted: silently baking a stale Go
# is the drift this exists to prevent.
GO_VERSION="${GO_VERSION:?set by build-image.sh}"
GO_SHA256="${GO_SHA256:?set by build-image.sh}"
GO_BUILD_IMAGE="${GO_BUILD_IMAGE:?set by build-image.sh}"
KUBECTL_VERSION="${KUBECTL_VERSION:?set by build-image.sh}"
KIND_VERSION="${KIND_VERSION:?set by build-image.sh}"
KIND_NODE_IMAGES="${KIND_NODE_IMAGES:?set by build-image.sh}"
GH_VERSION="${GH_VERSION:?set by build-image.sh}"

APT=(apt-get -o DPkg::Lock::Timeout=600 -y)
retry() { local n=8; for i in $(seq 1 $n); do "$@" && return 0; echo "retry $i/$n: $*"; sleep 5; done; return 1; }

# --- base packages ----------------------------------------------------------
retry "${APT[@]}" update
retry "${APT[@]}" install --no-install-recommends ca-certificates curl gnupg git make iproute2 zstd

# --- docker (kind's runtime); ubuntu joins the docker group -----------------
install -m 0755 -d /etc/apt/keyrings
retry curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
codename=$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
printf 'Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nSigned-By: /etc/apt/keyrings/docker.asc\n' "$codename" > /etc/apt/sources.list.d/docker.sources
retry "${APT[@]}" update
retry "${APT[@]}" install --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin
usermod -a -G docker ubuntu
systemctl enable docker

# --- go / kind / kubectl / gh (all pinned) ----------------------------------
# -f on every download: without it curl exits 0 on an HTTP error and writes the
# error page to the output file, so a 404 would install an HTML "kind" and the
# image would build clean and ship broken. Only go has a checksum to catch it.
fetch() { retry curl -fsSL --retry-connrefused -o "$1" "$2"; }

fetch /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
# The checksum the go-build image verifies its Go against.
echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c -
rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz
# go + a per-user GOBIN on PATH for interactive + non-interactive shells.
printf 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin\n' > /etc/profile.d/go.sh

fetch /usr/local/bin/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
chmod 0755 /usr/local/bin/kind

fetch /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
chmod 0755 /usr/local/bin/kubectl

fetch /tmp/gh.tgz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz"
tar -C /tmp -xzf /tmp/gh.tgz && install -m 0755 "/tmp/gh_${GH_VERSION}_linux_amd64/bin/gh" /usr/local/bin/gh

# --- inotify limits for 3 kind clusters (persist across boots) --------------
cat > /etc/sysctl.d/99-kind.conf <<EOF
fs.inotify.max_user_instances=512
fs.inotify.max_user_watches=524288
EOF

# --- pre-pull the heavy CI images so jobs skip the pull ---------------------
# Tags are injected by build-image.sh, so they cannot drift.
systemctl start docker
PREPULL_IMAGES=("$GO_BUILD_IMAGE" "registry:2")
# Unquoted on purpose: KIND_NODE_IMAGES is a space-separated list.
for img in $KIND_NODE_IMAGES; do PREPULL_IMAGES+=("$img"); done
# Fatal, not a warning: `|| echo` neutralised set -e, so a registry blip or a bad
# digest let the marker below be written and the image publish with an empty cache
# -- which only ever shows up as jobs being slower.
for img in "${PREPULL_IMAGES[@]}"; do
  retry docker pull "$img"
done

# Assert the cache holds everything, so a pull that somehow succeeded without
# landing the image cannot reach the snapshot.
for img in "${PREPULL_IMAGES[@]}"; do
  docker image inspect "$img" >/dev/null
done

# Readiness marker for the image-build poll.
touch /var/run/provision-done
