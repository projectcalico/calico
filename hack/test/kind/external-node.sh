#!/usr/bin/env bash

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

# external-node.sh - manage an "external node" for kind-based e2e tests.
#
# Creates (up) or removes (down) a container on the kind Docker network that is
# NOT a Kubernetes node, so the e2e framework can drive it over SSH to exercise
# ExternalNode-labeled specs (external->NodePort, doNotTrack DoS mitigation,
# packet-size/MTU, ...).
#
# The framework's externalnode client simply SSHes to EXT_IP as EXT_USER with
# EXT_KEY and runs commands (curl, sudo docker) there, so any SSH-able host with
# docker works. This mirrors the banzai/GCP external node (ubuntu user + SSH key
# + docker). Because the container sits on the kind network but is not a k8s
# node, Calico treats its traffic as coming from outside the cluster.
#
# `up` writes the node IP to <kind-dir>/external-node-ip and generates the SSH
# key at <kind-dir>/external-node-key(.pub). Callers point the e2e run at it with:
#   EXT_USER=ubuntu
#   EXT_IP=$(cat <kind-dir>/external-node-ip)
#   EXT_KEY=<kind-dir>/external-node-key
set -euo pipefail

KIND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="${EXTERNAL_NODE_NAME:-kind-external-node}"
NETWORK="${KIND_NETWORK:-kind}"
# docker-in-docker: provides an sshd-able base plus a Docker daemon for tests
# that launch client/server containers on the external node.
IMAGE="${EXTERNAL_NODE_IMAGE:-docker:28-dind}"
KEY="${KIND_DIR}/external-node-key"
IP_FILE="${KIND_DIR}/external-node-ip"

log() { echo "[external-node] $*"; }

up() {
	[[ -f "$KEY" ]] || ssh-keygen -t ed25519 -N "" -f "$KEY" -C external-node >/dev/null

	docker rm -f "$NAME" >/dev/null 2>&1 || true
	log "starting $NAME ($IMAGE) on network $NETWORK"
	docker run -d --privileged --name "$NAME" --network "$NETWORK" "$IMAGE" >/dev/null

	# Wait for the in-container dockerd (dind) to come up, and fail clearly if it
	# never does (otherwise `sudo docker` on the node fails later with an obscure
	# error mid-test).
	for _ in $(seq 1 30); do
		docker exec "$NAME" docker info >/dev/null 2>&1 && break
		sleep 1
	done
	if ! docker exec "$NAME" docker info >/dev/null 2>&1; then
		log "ERROR: dockerd did not become ready in $NAME"
		return 1
	fi

	docker exec "$NAME" apk add --no-cache openssh sudo iproute2 curl bash >/dev/null
	# Create the ubuntu user for the framework to SSH in as, and harden sshd to
	# key-only auth. NOTE: alpine's `adduser -D` leaves the account locked (! in
	# /etc/shadow), which silently blocks public-key auth; unlock it with a random
	# password. Password auth is disabled below regardless, so the password is
	# never a usable remote credential.
	docker exec "$NAME" sh -c '
		set -e
		adduser -D -s /bin/sh ubuntu 2>/dev/null || true
		echo "ubuntu:$(head -c 18 /dev/urandom | base64)" | chpasswd
		echo "ubuntu ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/ubuntu
		install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
		ssh-keygen -A >/dev/null
		printf "PasswordAuthentication no\nPermitRootLogin no\nPubkeyAuthentication yes\n" >> /etc/ssh/sshd_config
	'
	docker exec -i "$NAME" sh -c \
		'cat > /home/ubuntu/.ssh/authorized_keys \
		 && chmod 600 /home/ubuntu/.ssh/authorized_keys \
		 && chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys' \
		<"${KEY}.pub"
	docker exec "$NAME" /usr/sbin/sshd

	local ip
	ip="$(docker inspect "$NAME" --format "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}")"
	echo "$ip" >"$IP_FILE"

	# Confirm SSH is reachable before returning so the e2e run doesn't race sshd.
	for _ in $(seq 1 15); do
		if SSH_AUTH_SOCK= ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
			-o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i "$KEY" \
			"ubuntu@${ip}" true 2>/dev/null; then
			log "up: ip=$ip user=ubuntu key=$KEY"
			return 0
		fi
		sleep 1
	done
	log "ERROR: external node SSH not reachable at $ip"
	return 1
}

down() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	# Remove the generated IP file and keypair (regenerated on the next `up`) so
	# key material isn't left on disk / picked up as a CI artifact.
	rm -f "$IP_FILE" "$KEY" "${KEY}.pub"
	log "down: removed $NAME"
}

case "${1:-up}" in
up) up ;;
down) down ;;
*)
	echo "usage: $(basename "$0") up|down" >&2
	exit 1
	;;
esac
