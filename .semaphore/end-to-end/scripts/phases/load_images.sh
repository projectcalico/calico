#!/usr/bin/env bash
# load_images.sh - side-load PR-built e2e helper images onto the cluster.
#
# PR CI has no registry push credential (fork PRs are untrusted), so an image
# built from the PR source cannot be pushed to quay for the nodes to pull. For
# the rapidclient image (used by the packet-size and maglev tests) we instead
# build it locally and import it straight into each node's container runtime:
#   - worker nodes  -> containerd `k8s.io` namespace (pods run it, PullPolicy=Never)
#   - external node -> docker (maglev runs it via `docker run`)
# and export RAPIDCLIENT_TAG so images.RapidClientImage() pins that exact copy.
#
# Scope: only the local-binary gcp-kubeadm PR path. Node access here relies on the
# gcp-kubeadm CRC terraform outputs + master_ssh_key, which don't exist on other
# providers; those runs skip this phase and fall back to the published :latest
# (unchanged behaviour). Scheduled runs (no RUN_LOCAL_TESTS) test the published
# hashrelease images, so they also skip and use :latest.
#
# Required env:
#   BZ_LOCAL_DIR, HOME
# Optional env (set by the gcp-kubeadm block / configure.sh):
#   RUN_LOCAL_TESTS, PROVISIONER, SEMAPHORE_GIT_PR_NUMBER, SEMAPHORE_GIT_SHA,
#   EXT_IP, EXT_KEY, EXT_USER
# Exports consumed by later phases:
#   RAPIDCLIENT_TAG, K8S_E2E_DOCKER_EXTRA_FLAGS
#
# Sourced from body_*.sh (inherits `set -eo pipefail`, so any build/load failure
# aborts the job — preferable to a later ErrImageNeverPull mid-test).

if [[ -z "${RUN_LOCAL_TESTS:-}" || "${PROVISIONER:-}" != "gcp-kubeadm" ]]; then
  echo "[INFO] load_images: skipping (only for local-binary gcp-kubeadm PR builds;" \
       "PROVISIONER=${PROVISIONER:-unset}, RUN_LOCAL_TESTS=${RUN_LOCAL_TESTS:-unset})." \
       "Tests will use the published rapidclient :latest."
else
  # Immutable, unique per PR (falls back to the commit sha off-PR). Pods pin this
  # tag with ImagePullPolicy=Never, so it must match what we import below exactly.
  if [[ -n "${SEMAPHORE_GIT_PR_NUMBER:-}" ]]; then
    _tag="pr-${SEMAPHORE_GIT_PR_NUMBER}"
  else
    _tag="e2e-${SEMAPHORE_GIT_SHA:0:12}"
  fi
  _img="quay.io/tigeradev/rapidclient:${_tag}"

  echo "[INFO] load_images: building ${_img} from local source (no registry push)"
  make -C "${HOME}/calico/e2e/images/rapidclient" image TAG_NAME="${_tag}"

  # --- worker nodes: import into containerd's k8s.io namespace ---------------
  _plat="${BZ_LOCAL_DIR}/crc/kubeadm/1.6"
  _key="${_plat}/master_ssh_key"
  _tf_out="${_plat}/terraform_output.json"
  if [[ ! -f "${_tf_out}" ]]; then echo "[ERROR] load_images: ${_tf_out} not found"; exit 1; fi
  if [[ ! -f "${_key}" ]]; then echo "[ERROR] load_images: ssh key ${_key} not found"; exit 1; fi
  _ssh_opts=(-i "${_key}" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=30)

  mapfile -t _node_ips < <(jq -r '.node_connect_commands.value[]' "${_tf_out}" \
                             | grep -oE 'ubuntu@[0-9.]+' | cut -d@ -f2)
  if [[ ${#_node_ips[@]} -eq 0 ]]; then
    echo "[ERROR] load_images: no worker node IPs parsed from ${_tf_out}"; exit 1
  fi

  # Serialize the image once and reuse the tarball for every node (docker save is
  # the expensive part; re-running it per node would re-export the whole image).
  # The EXIT trap frees the tarball even if a save/ssh/load aborts the job under
  # `set -eo pipefail` (this phase is sourced and nothing else sets an EXIT trap).
  _tar="$(mktemp -t rapidclient.XXXXXX.tar)"
  trap 'rm -f "${_tar}"' EXIT
  docker save "${_img}" -o "${_tar}"

  echo "[INFO] load_images: importing into containerd on ${#_node_ips[@]} worker node(s): ${_node_ips[*]}"
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

  # Pin the tests to the loaded image and forward the tag into the e2e container
  # (run_tests.sh passes ${K8S_E2E_DOCKER_EXTRA_FLAGS} to its `docker run`).
  export RAPIDCLIENT_TAG="${_tag}"
  export K8S_E2E_DOCKER_EXTRA_FLAGS="--env RAPIDCLIENT_TAG ${K8S_E2E_DOCKER_EXTRA_FLAGS:-}"
  echo "[INFO] load_images: RAPIDCLIENT_TAG=${RAPIDCLIENT_TAG} (pods pin this tag, ImagePullPolicy=Never)"
fi
