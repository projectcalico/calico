#!/usr/bin/env bash
# Checks vpp_metadata.sh against the twelve e2e-vpp matrix cells. Run by hand:
# no cluster, no network. Asserts each cell's prefix and that all twelve differ,
# because two cells previously collided and silently overwrote each other.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
readonly BUILDER=./vpp_metadata.sh
readonly WF=e2e-vpp-master-1788192000   # hour-aligned epoch => 2026-08-31 16:00
readonly BASE=gs://vpp-results/2026-08-31

fails=0
got_all=()

# check <expected-suffix-after-BASE> <env>...
# A later assignment wins, so a cell can override RELEASE_STREAM.
check() {
  local want="${BASE}/$1"; shift
  local got
  got=$(env -i PATH="${PATH}" ARGO_WORKFLOW_NAME="${WF}" CI_GIT_REF_TYPE=NIGHTLY \
        RELEASE_STREAM=master "$@" "${BUILDER}")
  got_all+=("${got}")
  if [[ "${got}" != "${want}" ]]; then
    printf 'FAIL\n  want %s\n  got  %s\n' "${want}" "${got}"
    fails=$((fails + 1))
  fi
}

check master/aws-eks/calico-vpp-eks.yaml/16:00 \
  PROVISIONER=aws-eks VPP_MANIFEST_FILE=calico-vpp-eks.yaml
check master/aws-eks/calico-vpp-eks-dpdk.yaml/HUGEPAGES/16:00 \
  PROVISIONER=aws-eks VPP_MANIFEST_FILE=calico-vpp-eks-dpdk.yaml ENABLE_HUGEPAGES=true
check master/aws-kubeadm/calico-vpp-nohuge.yaml/16:00 \
  PROVISIONER=aws-kubeadm VPP_MANIFEST_FILE=calico-vpp-nohuge.yaml
check master/aws-kubeadm/calico-vpp-dpdk.yaml/HUGEPAGES/16:00 \
  PROVISIONER=aws-kubeadm VPP_MANIFEST_FILE=calico-vpp-dpdk.yaml ENABLE_HUGEPAGES=true
check master/aws-kubeadm/calico-vpp-dpdk.yaml/HUGEPAGES/IPSEC/16:00 \
  PROVISIONER=aws-kubeadm VPP_MANIFEST_FILE=calico-vpp-dpdk.yaml \
  ENABLE_HUGEPAGES=true ENABLE_VPP_IPSEC=true
# The OpenShift cells set no manifest; the '//' is the historical shape.
check master/aws-openshift//16:00 \
  PROVISIONER=aws-openshift
check master/aws-openshift//Iptables/16:00 \
  PROVISIONER=aws-openshift DATAPLANE=CalicoIptables
check master/gcp-kubeadm/calico-vpp-nohuge.yaml/16:00 \
  PROVISIONER=gcp-kubeadm VPP_MANIFEST_FILE=calico-vpp-nohuge.yaml
check master/gcp-kubeadm/calico-vpp-dpdk.yaml/HUGEPAGES/16:00 \
  PROVISIONER=gcp-kubeadm VPP_MANIFEST_FILE=calico-vpp-dpdk.yaml ENABLE_HUGEPAGES=true
# VXLAN is what stops this colliding with the cell above it.
check master/gcp-kubeadm/calico-vpp-dpdk.yaml/HUGEPAGES/VXLAN/16:00 \
  PROVISIONER=gcp-kubeadm VPP_MANIFEST_FILE=calico-vpp-dpdk.yaml \
  ENABLE_HUGEPAGES=true ENCAPSULATION_TYPE=VXLAN
check master/gcp-kubeadm/calico-vpp-dpdk.yaml/HUGEPAGES/WG/16:00 \
  PROVISIONER=gcp-kubeadm VPP_MANIFEST_FILE=calico-vpp-dpdk.yaml \
  ENABLE_HUGEPAGES=true ENABLE_WIREGUARD=true
# The regression cell is the only one that moves the stream segment.
check v3.28/gcp-kubeadm/calico-vpp-nohuge.yaml/16:00 \
  PROVISIONER=gcp-kubeadm VPP_MANIFEST_FILE=calico-vpp-nohuge.yaml RELEASE_STREAM=v3.28

uniq_count=$(printf '%s\n' "${got_all[@]}" | sort -u | wc -l)
if [[ "${uniq_count}" -ne "${#got_all[@]}" ]]; then
  printf 'FAIL: %s cells produced only %s distinct prefixes\n' \
    "${#got_all[@]}" "${uniq_count}"
  fails=$((fails + 1))
fi

# publishes_nothing <label> <env>...
publishes_nothing() {
  local label="$1"; shift
  local out
  out=$(env -i PATH="${PATH}" "$@" "${BUILDER}")
  if [[ -n "${out}" ]]; then
    printf 'FAIL: %s should yield no prefix, got %s\n' "${label}" "${out}"
    fails=$((fails + 1))
  fi
}

# Only the CronWorkflow is labelled NIGHTLY, so nothing else may write to the
# bucket the maintainers read -- a `[cron-ci]` run on a PR least of all.
for rt in PR MERGE TAG BRANCH ''; do
  publishes_nothing "CI_GIT_REF_TYPE=${rt:-<unset>}" \
    ARGO_WORKFLOW_NAME="${WF}" CI_GIT_REF_TYPE="${rt}" \
    RELEASE_STREAM=master PROVISIONER=gcp-kubeadm
done

# Belt and braces: even labelled NIGHTLY, a name carrying no epoch has no anchor
# to share between steps. The 5-digit suffix must not read as one.
for name in e2e-vpp-13133-pr-83729 e2e-vpp-13133-pr-m5xdw ''; do
  publishes_nothing "name ${name:-<unset>}" \
    ARGO_WORKFLOW_NAME="${name}" CI_GIT_REF_TYPE=NIGHTLY \
    RELEASE_STREAM=master PROVISIONER=gcp-kubeadm
done

if [[ "${fails}" -eq 0 ]]; then
  printf 'ok: %s cells, all distinct; non-scheduled runs publish nothing\n' \
    "${#got_all[@]}"
else
  echo "${fails} failure(s)"
  exit 1
fi
