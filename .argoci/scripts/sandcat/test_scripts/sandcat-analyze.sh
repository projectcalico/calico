#!/usr/bin/env bash
# Behaviour test for `sandcat.sh analyze` and `cut-off`. The analyzed marker,
# which stops the epilogue from analyzing again, is written only when the
# analysis succeeded, and cut-off records a job without analyzing it. sandcat
# is stubbed, so no binary, network or cluster is needed.

set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandcat.sh}"
pass=0
fail=0
homes=()
trap 'rm -rf ${homes[@]+"${homes[@]}"}' EXIT

export SANDCAT_INGEST_TOKEN=t SANDCAT_UPLOAD_URL=https://sandcat.invalid SANDCAT_CALICO_MCP=0

newhome() {
  HOME=$(mktemp -d)
  export HOME
  homes+=("${HOME}")
  mkdir -p "${HOME}/.local/bin"
  cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${HOME}/argv"
exit "${STUB_RC:-0}"
STUB
  chmod +x "${HOME}/.local/bin/sandcat"
  echo '{}' > "${HOME}/report.json"
}

check() {
  local name="$1" want_marker="$2"
  local rc=0
  (cd "${HOME}" && "${SCRIPT}" analyze --report "${HOME}/report.json" --source-dir "${HOME}") >/dev/null 2>&1 || rc=$?
  local got=no
  [[ -f "${HOME}/.sandcat-analyzed" ]] && got=yes
  if [[ "${rc}" == 0 && "${got}" == "${want_marker}" ]]; then
    echo "PASS ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name} (rc=${rc} marker=${got} want=${want_marker})"
    fail=$((fail + 1))
  fi
}

newhome
STUB_RC=0 check "a successful analysis writes the marker" yes

newhome
STUB_RC=1 check "a failed analysis leaves no marker, so the epilogue retries" no

newhome
(cd "${HOME}" && "${SCRIPT}" cut-off --after 12m --source-dir "${HOME}") >/dev/null 2>&1
if grep -q -- '^analyze --cut-off-after 12m ' "${HOME}/argv" && ! grep -q -- '--ginkgo-report' "${HOME}/argv"; then
  echo "PASS cut-off records the stopped analysis without analyzing"
  pass=$((pass + 1))
else
  echo "FAIL cut-off records the stopped analysis without analyzing: $(cat "${HOME}/argv" 2>/dev/null)"
  fail=$((fail + 1))
fi

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
