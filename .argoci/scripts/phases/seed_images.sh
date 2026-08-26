#!/usr/bin/env bash
# seed_images.sh - pre-seed the e2e workload images into each node's containerd.
#
# The kubeadm clusters cannot reach Docker Hub, registry.k8s.io or gcr.io from
# the nodes, so a test workload pod sits in ErrImagePull until it times out. The
# runner does have registry egress, so pull there once, ship the tarball over
# ssh and import it into the k8s.io containerd namespace. Every workload pod
# sets ImagePullPolicy: IfNotPresent, so a seeded image is used without a pull.
#
# Scope: providers whose nodes are reachable over ssh, i.e. the ones bz builds
# from terraform (gcp-kubeadm, aws-kubeadm). Managed providers have no key here
# and no pull problem; those runs skip this phase.
#
# Required env:
#   BZ_LOCAL_DIR
#
# Sourced from body_standard.sh. Seeding is best-effort: a failure here leaves
# the pods pulling for themselves, which is the behaviour without this phase, so
# it must not abort the job under the caller's `set -eo pipefail`.

# Keep in sync with e2e/pkg/utils/images/images.go. TestImagesAreSeeded fails if
# a Linux workload image is added there without being listed here.
_seed_images=(
  "docker.io/alpine:3"
  "docker.io/alpine/socat:1.8.0.1"
  "docker.io/networkstatic/iperf3:latest"
  "docker.io/nicolaka/netshoot:v0.13"
  "gcr.io/kubernetes-e2e-test-images/test-webserver:1.0"
  "registry.k8s.io/e2e-test-images/agnhost:2.47"
)

_seed_images_main() {
  local _tf_out _key _plat _tar _ip _img
  local -a _node_ips _ssh_opts

  _tf_out="$(ls "${BZ_LOCAL_DIR}"/crc/*/*/terraform_output.json 2>/dev/null | head -1)"
  if [[ -z "${_tf_out}" ]]; then
    echo "[INFO] seed_images: skipping, no terraform output under ${BZ_LOCAL_DIR}/crc (managed provider?)"
    return 0
  fi
  _plat="$(dirname "${_tf_out}")"
  _key="${_plat}/master_ssh_key"
  if [[ ! -f "${_key}" ]]; then
    echo "[INFO] seed_images: skipping, no ssh key at ${_key}"
    return 0
  fi

  # Infra nodes are schedulable on some platforms, so seed them too.
  mapfile -t _node_ips < <(jq -r '.node_connect_commands.value[]?, .infra_node_connect_commands.value[]?' "${_tf_out}" \
                             | grep -oE '@[0-9.]+' | cut -d@ -f2 | sort -u)
  if [[ ${#_node_ips[@]} -eq 0 ]]; then
    echo "[WARN] seed_images: no node IPs parsed from ${_tf_out}, skipping"
    return 0
  fi

  for _img in "${_seed_images[@]}"; do
    if ! docker pull --quiet "${_img}"; then
      echo "[WARN] seed_images: could not pull ${_img} on the runner, skipping the whole phase"
      return 0
    fi
  done

  # One tarball for every node: docker save is the expensive part and the
  # payload is identical per node.
  _tar="$(mktemp -t e2e-workload-images.XXXXXX.tar)"
  if ! docker save "${_seed_images[@]}" -o "${_tar}"; then
    echo "[WARN] seed_images: docker save failed, skipping"
    rm -f "${_tar}"
    return 0
  fi

  _ssh_opts=(-i "${_key}" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=30)
  echo "[INFO] seed_images: importing ${#_seed_images[@]} images into containerd on ${#_node_ips[@]} node(s): ${_node_ips[*]}"
  for _ip in "${_node_ips[@]}"; do
    if ssh "${_ssh_opts[@]}" "ubuntu@${_ip}" -- 'sudo ctr -n k8s.io images import -' < "${_tar}"; then
      echo "[INFO]   -> ${_ip} ok"
    else
      echo "[WARN]   -> ${_ip} import failed; its pods will pull for themselves"
    fi
  done

  rm -f "${_tar}"
}

_seed_images_main || echo "[WARN] seed_images: phase failed, pods will pull for themselves"
