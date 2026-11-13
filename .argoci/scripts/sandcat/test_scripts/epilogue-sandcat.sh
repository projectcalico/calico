#!/usr/bin/env bash
# Behaviour test for the sandcat fallback in global_epilogue.sh: a hung analysis
# cannot keep the cluster from being destroyed, and a run whose only junit is
# the stern check records a build failure instead of analyzing that junit.
# bz, artifact, gsutil, curl and sandcat.sh are stubbed.

set -uo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EPILOGUE="${1:-${SCRIPTS}/global_epilogue.sh}"
MERGE_JUNIT="${SCRIPTS}/merge_junit.py"
pass=0
fail=0
roots=()
trap 'rm -rf ${roots[@]+"${roots[@]}"}' EXIT

# The epilogue finds sandcat.sh beside itself, so it runs from a copy.
newroot() {
  ROOT=$(mktemp -d)
  roots+=("${ROOT}")
  mkdir -p "${ROOT}/scripts/sandcat" "${ROOT}/bin" "${ROOT}/home" "${ROOT}/local" \
    "${ROOT}/logs" "${ROOT}/src/report" "${ROOT}/report"
  cp "${EPILOGUE}" "${ROOT}/scripts/global_epilogue.sh"
  cp "${MERGE_JUNIT}" "${ROOT}/scripts/merge_junit.py"
  for tool in bz artifact gsutil curl; do
    printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\n' "${tool}" "${ROOT}" > "${ROOT}/bin/${tool}"
    chmod +x "${ROOT}/bin/${tool}"
  done
  cat > "${ROOT}/scripts/sandcat/sandcat.sh" <<STUB
#!/usr/bin/env bash
echo "sandcat \$*" >> "${ROOT}/calls.log"
if [[ "\$1" == analyze ]]; then
  echo \$\$ > "${ROOT}/analyze.pid"
  exec sleep "\${STUB_ANALYZE_SECONDS:-0}"
fi
exit 0
STUB
  chmod +x "${ROOT}/scripts/sandcat/sandcat.sh"
}

run_epilogue() {
  env -u GITHUB_ACCESS_TOKEN PATH="${ROOT}/bin:${PATH}" HOME="${ROOT}/home" \
    BZ_HOME="${ROOT}" BZ_LOCAL_DIR="${ROOT}/local" BZ_LOGS_DIR="${ROOT}/logs" \
    REPORT_DIR="${ROOT}/report" CI_HOME="${ROOT}" CI_GIT_DIR=src TEST_TYPE=k8s-e2e \
    CI_STEP_EXIT_CODE=1 VPP_RESULTS_PREFIX="" "$@" \
    timeout 90 bash "${ROOT}/scripts/global_epilogue.sh" >/dev/null 2>&1
}

check() {
  local name="$1"
  shift
  if "$@"; then
    echo "PASS ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name}"
    fail=$((fail + 1))
  fi
}

line_of() {
  grep -n -m1 -- "$1" "${ROOT}/calls.log" | cut -d: -f1
}

newroot
echo '<testsuite name="e2e" tests="1" failures="1"/>' > "${ROOT}/report/junit.xml"
start=${SECONDS}
run_epilogue STUB_ANALYZE_SECONDS=600 SANDCAT_EPILOGUE_TIMEOUT=2s
elapsed=$((SECONDS - start))
check "a hung analysis is cut off at its limit" test "${elapsed}" -lt 60
check "the cluster is destroyed after the hung analysis" \
  test -n "$(line_of 'bz destroy')" -a "$(line_of 'sandcat analyze')" -lt "$(line_of 'bz destroy' || echo 0)"
check "the hung analysis left no process behind" bash -c "! kill -0 \$(cat '${ROOT}/analyze.pid') 2>/dev/null"

newroot
echo '<testsuite name="stern" tests="1"/>' > "${ROOT}/report/junit-stern.xml"
run_epilogue
check "a stern-only junit is not analyzed" bash -c "! grep -q 'sandcat analyze' '${ROOT}/calls.log'"
check "a stern-only junit records a build failure" grep -q 'sandcat build-failure' "${ROOT}/calls.log"

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
