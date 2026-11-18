#!/usr/bin/env bash
# Tests `sandcat.sh analyze` and `cut-off` against a stubbed sandcat: the database gate, its flags, and the analyzed marker.

set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandcat.sh}"
pass=0
fail=0
homes=()
trap 'rm -rf ${homes[@]+"${homes[@]}"}' EXIT

export SANDCAT_DB_URL=postgres://broker.invalid SANDCAT_DB_TOKEN=t
# analyze needs no calico-mcp, so no download is attempted even with it on.
unset SANDCAT_CALICO_MCP SANDCAT_UPLOAD_URL SANDCAT_INGEST_TOKEN

newhome() {
  HOME=$(mktemp -d)
  export HOME
  homes+=("${HOME}")
  mkdir -p "${HOME}/.local/bin"
  cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
echo "$*" > "${HOME}/args"
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
if [[ ! -f "${HOME}/args" ]] || grep -qE -- '--upload|--agent' "${HOME}/args"; then
  echo "FAIL analyze passes no ingest or agent flags ($(cat "${HOME}/args" 2>/dev/null || echo 'sandcat not run'))"
  fail=$((fail + 1))
else
  echo "PASS analyze passes no ingest or agent flags"
  pass=$((pass + 1))
fi

newhome
STUB_RC=1 check "a failed analysis writes the marker, so the epilogue does not run it again" yes

newhome
rm "${HOME}/.local/bin/sandcat"
SANDCAT_BIN_DOWNLOAD_TOKEN='' check "an analysis that never started leaves no marker, so the epilogue runs it" no

newhome
(cd "${HOME}" && "${SCRIPT}" cut-off --after 12m --source-dir "${HOME}") >/dev/null 2>&1
if grep -q -- '^analyze --cut-off-after 12m ' "${HOME}/args" 2>/dev/null && ! grep -q -- '--ginkgo-report' "${HOME}/args"; then
  echo "PASS cut-off records the stopped analysis without analyzing"
  pass=$((pass + 1))
else
  echo "FAIL cut-off records the stopped analysis without analyzing: $(cat "${HOME}/args" 2>/dev/null)"
  fail=$((fail + 1))
fi

newhome
out=$(cd "${HOME}" && env -u SANDCAT_DB_TOKEN "${SCRIPT}" analyze --report "${HOME}/report.json" --source-dir "${HOME}" 2>&1)
if [[ ! -f "${HOME}/args" && "${out}" == *"unset: SANDCAT_DB_TOKEN"* ]]; then
  echo "PASS a missing database secret skips analyze and names it"
  pass=$((pass + 1))
else
  echo "FAIL a missing database secret skips analyze and names it (${out})"
  fail=$((fail + 1))
fi

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
