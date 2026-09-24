#!/usr/bin/env bash
# load_images.sh - side-load PR-built e2e helper images onto the cluster.
#
# PR CI has no registry push credential (fork PRs are untrusted), so an image
# built from the PR source cannot be pushed to quay for the nodes to pull. For
# the rapidclient image (used by the packet-size and maglev tests) we instead
# build it locally under the tag the tests already use and import it into each
# node's container runtime:
#   - cluster nodes -> containerd `k8s.io` namespace (pods run it)
#   - external node -> docker (maglev runs it via `docker run`)
# Pods use ImagePullPolicy: IfNotPresent, so the imported copy is used as-is.
#
# Scope: only the local-binary gcp-kubeadm PR path. Node access here relies on the
# gcp-kubeadm CRC terraform outputs + master_ssh_key, which don't exist on other
# providers; those runs skip this phase and pull the published image. Scheduled
# runs (no RUN_LOCAL_TESTS) test the published hashrelease images, so they also
# skip.
#
# Required env:
#   BZ_LOCAL_DIR, HOME
# Optional env (set by the gcp-kubeadm block / configure.sh):
#   RUN_LOCAL_TESTS, PROVISIONER, EXT_IP, EXT_KEY, EXT_USER
#
# Sourced from body_*.sh (inherits `set -eo pipefail`, so any build/load failure
# aborts the job, rather than silently testing the published image instead of the
# PR's).

if [[ -z "${RUN_LOCAL_TESTS:-}" || "${PROVISIONER:-}" != "gcp-kubeadm" ]]; then
  echo "[INFO] load_images: skipping (only for local-binary gcp-kubeadm PR builds;" \
       "PROVISIONER=${PROVISIONER:-unset}, RUN_LOCAL_TESTS=${RUN_LOCAL_TESTS:-unset})." \
       "Tests will pull the published rapidclient image."
else

  # Must match rapidClientImage in e2e/pkg/utils/images/images.go: the pods look up
  # this exact reference, and IfNotPresent then uses what we import below.
  _img="quay.io/tigeradev/rapidclient:latest"

  echo "[INFO] load_images: building ${_img} from local source (no registry push)"
  make -C "${HOME}/calico/e2e/images/rapidclient" image TAG_NAME="latest"

  # --- cluster nodes: import into containerd's k8s.io namespace --------------
  _plat="${BZ_LOCAL_DIR}/crc/kubeadm/1.6"
  _key="${_plat}/master_ssh_key"
  _tf_out="${_plat}/terraform_output.json"
  if [[ ! -f "${_tf_out}" ]]; then echo "[ERROR] load_images: ${_tf_out} not found"; exit 1; fi
  if [[ ! -f "${_key}" ]]; then echo "[ERROR] load_images: ssh key ${_key} not found"; exit 1; fi
  _ssh_opts=(-i "${_key}" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=30)

  # Infra nodes are schedulable on some platforms, so a pod can land on one.
  mapfile -t _node_ips < <(jq -r '.node_connect_commands.value[]?, .infra_node_connect_commands.value[]?' "${_tf_out}" \
                             | grep -oE 'ubuntu@[0-9.]+' | cut -d@ -f2 | sort -u)
  if [[ ${#_node_ips[@]} -eq 0 ]]; then
    echo "[ERROR] load_images: no node IPs parsed from ${_tf_out}"; exit 1
  fi

  # Serialize the image once and reuse the tarball for every node (docker save is
  # the expensive part; re-running it per node would re-export the whole image).
  # The EXIT trap frees the tarball even if a save/ssh/load aborts the job under
  # `set -eo pipefail` (this phase is sourced and nothing else sets an EXIT trap).
  _tar="$(mktemp -t rapidclient.XXXXXX.tar)"
  trap 'rm -f "${_tar}"' EXIT
  docker save "${_img}" -o "${_tar}"

  echo "[INFO] load_images: importing into containerd on ${#_node_ips[@]} node(s): ${_node_ips[*]}"
  for _ip in "${_node_ips[@]}"; do
    echo "[INFO]   -> ${_ip} (containerd)"
    ssh "${_ssh_opts[@]}" "ubuntu@${_ip}" -- 'sudo ctr -n k8s.io images import -' < "${_tar}"
  done

  # --- external node: load into docker (maglev uses `docker run`) ------------
  if [[ -n "${EXT_IP:-}" && -n "${EXT_KEY:-}" ]]; then
    echo "[INFO] load_images: loading into external node docker (${EXT_IP})"
    ssh -i "${EXT_KEY}" \
      -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=30 \
      "${EXT_USER:-ubuntu}@${EXT_IP}" -- 'sudo docker load' < "${_tar}"
  fi

  rm -f "${_tar}"
  trap - EXIT  # cleanup done on the happy path; don't leak the trap into run_tests.sh

  echo "[INFO] load_images: ${_img} loaded; pods will use it instead of pulling"
fi
