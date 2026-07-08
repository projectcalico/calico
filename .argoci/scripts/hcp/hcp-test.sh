#!/usr/bin/env bash
# Vendored from tigera/banzai-utils ocp-hcp/hcp-test.sh, adapted for ArgoCI.
# Env-driven (BZ_PROFILES_PATH/BZ_SECRETS_PATH/BZ_PATH); the ArgoCI HCP
# wrapper (.argoci/scripts/phases/hcp.sh) + global_prologue.sh set those.

BZ_PROFILES_PATH=${BZ_PROFILES_PATH:=$HOME/bzprofiles}
BZ_SECRETS_PATH=${BZ_SECRETS_PATH:=$HOME/.banzai/secrets}
BZ=${BZ_PATH:=$HOME/.local/bin/bz}
BZ_HCP_STATUS_PATH=${BZ_HCP_STATUS_PATH:=$(find "$BZ_PROFILES_PATH" -maxdepth 1 -type f -name "hcp-*.status" -printf "%T@ %p\n" | sort -rn -k1 | head -n 1 | cut -d" " -f2)}
K8S_E2E_FLAGS=${K8S_E2E_FLAGS:="--ginkgo.focus=(\[sig-calico\]|\[Conformance\]) --ginkgo.skip=(\[Slow\]|\[Disruptive\]|\[DataPath\]|Proxy.version.v1.should.proxy.through.a.service.and.a.pod|WireGuard)"}

echo "[INFO] Using $BZ_HCP_STATUS_PATH to extract clusters"
clusters=$(cut -d: -f2 "$BZ_HCP_STATUS_PATH" | tr -d '\n')

if [[ -z "$clusters" ]]; then
  echo "[ERROR] No clusters have been declared to be tested"
  exit 1
fi

echo "[INFO] Creating $BZ_PROFILES_PATH/.report to store test reports"
echo mkdir -p "$BZ_PROFILES_PATH/.report"
mkdir -p "$BZ_PROFILES_PATH/.report"

exit_status=0

for cluster in $clusters; do
  if [[ -d $BZ_PROFILES_PATH/$cluster ]]; then
    cd "$BZ_PROFILES_PATH/$cluster" || exit 1
    cluster_type=$(awk '/CALIENT_CLUSTER_TYPE:/{print $2}' Taskvars.yml | tr -d "\n")
    echo "[INFO] Running tests on $cluster_type cluster $cluster using $K8S_E2E_FLAGS"
    echo K8S_E2E_FLAGS="$K8S_E2E_FLAGS" "$BZ" tests
    K8S_E2E_FLAGS="$K8S_E2E_FLAGS" "$BZ" tests; (( exit_status = exit_status || $? ))
    if [[ -f "$BZ_PROFILES_PATH/$cluster/.local/report/k8s-e2e/junit_1.xml" ]]; then
      echo "[INFO] Moving test results to $BZ_PROFILES_PATH/.report"
      echo cp "$BZ_PROFILES_PATH/$cluster/.local/report/k8s-e2e/junit_1.xml" "$BZ_PROFILES_PATH/.report/junit_${cluster}_1.xml"
      cp "$BZ_PROFILES_PATH/$cluster/.local/report/k8s-e2e/junit_1.xml" "$BZ_PROFILES_PATH/.report/junit_${cluster}_1.xml"
      echo "[INFO] Rewriting testcase name to match the correct cluster"
      echo sed -i "s/<testcase name=\"/<testcase name=\"[cluster-${cluster}]/" "$BZ_PROFILES_PATH/.report/junit_${cluster}_1.xml"
      sed -i "s/<testcase name=\"/<testcase name=\"[cluster-${cluster}]/" "$BZ_PROFILES_PATH/.report/junit_${cluster}_1.xml"
    fi
  fi
done

echo "[INFO] Tests finished with $exit_status"
exit $exit_status
