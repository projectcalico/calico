#!/usr/bin/env bash
# Behaviour test for `sandcat.sh inline-env`, mostly its refusals. sandcat and
# calico-mcp are stubbed, so no network, cluster or Gemini key is needed.

set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandcat.sh}"
ORIGINAL_PATH="${PATH}"

# Callers eval the payload, so this exact key set is a contract.
PAYLOAD_KEYS=(
  SANDCAT_INLINE_BIN
  SANDCAT_INLINE_CALICO_MCP_BIN
  SANDCAT_INLINE_PR_CONTEXT
  SANDCAT_INLINE_GEMINI_KEY
  SANDCAT_INLINE_SHA
  SANDCAT_SIG_DIR
  SANDCAT_MAX_DIAGNOSES
  SANDCAT_TOTAL_BUDGET
)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "${TEST_ROOT}"' EXIT
pass=0
fail=0

# check <name> <want_rc> [pattern...] -- a pattern prefixed with ! must NOT appear.
# Streams are captured separately: callers eval stdout, so every line on it must
# be a payload assignment.
check() {
  local name="$1" want_rc="$2"
  shift 2
  local out err rc ok=1 pat line
  local errfile
  errfile=$(mktemp)
  out=$("${SCRIPT}" inline-env --kubeconfig /tmp/kubeconfig 2>"${errfile}")
  rc=$?
  err=$(cat "${errfile}")
  rm -f "${errfile}"
  if [[ "${rc}" != "${want_rc}" ]]; then
    ok=0
    echo "  rc=${rc} want=${want_rc}"
  fi
  local -a keys=()
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    if [[ ! "${line}" =~ ^[A-Z][A-Z0-9_]*= ]]; then
      ok=0
      echo "  non-assignment on stdout: ${line}"
      continue
    fi
    # A leaked assignment such as PATH=... would corrupt the caller's environment.
    if [[ " ${PAYLOAD_KEYS[*]} " != *" ${line%%=*} "* ]]; then
      ok=0
      echo "  unexpected key on stdout: ${line%%=*}"
    fi
    keys+=("${line%%=*}")
  done <<<"${out}"
  # The payload must reach stdout, not stderr where callers never see it.
  if [[ "${want_rc}" == 0 && "${#keys[@]}" != "${#PAYLOAD_KEYS[@]}" ]]; then
    ok=0
    echo "  stdout carried ${#keys[@]} of ${#PAYLOAD_KEYS[@]} payload keys"
  fi
  # A refusal must print nothing on stdout.
  if [[ "${want_rc}" != 0 && -n "${out}" ]]; then
    ok=0
    echo "  stdout not empty on a refusal"
  fi
  out="${out}"$'\n'"${err}"
  for pat in "$@"; do
    if [[ "${pat}" == '!'* ]]; then
      if grep -qF -- "${pat#!}" <<<"${out}"; then
        ok=0
        echo "  unexpected: ${pat#!}"
      fi
    elif ! grep -qF -- "${pat}" <<<"${out}"; then
      ok=0
      echo "  missing: ${pat}"
    fi
  done
  if [[ "${ok}" == 1 ]]; then
    echo "PASS ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name}"
    sed 's/^/    /' <<<"${out}"
    fail=$((fail + 1))
  fi
}

# A fresh HOME per case, since sandcat.sh caches both binaries under it.
newhome() {
  HOME=$(mktemp -d -p "${TEST_ROOT}")
  export HOME
  mkdir -p "${HOME}/.local/bin"
  # STUB_MCP_RC sets check-mcp's exit code (3 is "calico-mcp unavailable");
  # STUB_PR=0 is a branch run, where fetch-pr writes nothing.
  cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  check-mcp)
    # The real one prints its verdict on stdout -- that is the leak this test
    # exists to catch, so the stub must be just as chatty. The `(` and `;` are
    # from its no-reachability variant, which eval treats as a syntax error
    # rather than an unknown command.
    echo "calico-mcp ok: 18 tools registered (no reachability probe; unverified)"
    exit "${STUB_MCP_RC:-0}"
    ;;
  fetch-pr)
    [[ "${STUB_PR:-1}" == "1" ]] || exit 1
    out=""
    while [[ $# -gt 0 ]]; do
      [[ "$1" == "--out" ]] && out="$2"
      shift
    done
    echo '{"body":"stub"}' > "${out}"
    ;;
  *) exit 0 ;;
esac
STUB
  chmod +x "${HOME}/.local/bin/sandcat"
  CALICO_MCP_LOCAL_BIN="${HOME}/.local/bin/calico-mcp"
  export CALICO_MCP_LOCAL_BIN
  printf '#!/bin/sh\necho "calico-mcp 0.0-stub"\n' > "${CALICO_MCP_LOCAL_BIN}"
  chmod +x "${CALICO_MCP_LOCAL_BIN}"
  SANDCAT_PR_CONTEXT_FILE="${HOME}/pr-context.json"
  export SANDCAT_PR_CONTEXT_FILE
  unset SANDCAT_GEMINI_KEY GEMINI_API_KEY SANDCAT_CALICO_MCP STUB_MCP_RC STUB_PR
  unset SANDCAT_SIG_DIR SANDCAT_MAX_DIAGNOSES SANDCAT_TOTAL_BUDGET
  # Restored per case so a shadowed gcloud never leaks into a later case.
  PATH="${ORIGINAL_PATH}"
  export PATH
}

newhome
check "no key: off, and says so" 1 \
  "inline per-spec diagnosis off" "neither SANDCAT_GEMINI_KEY nor GEMINI_API_KEY"

newhome
export SANDCAT_GEMINI_KEY=key-a
check "everything present" 0 \
  "inline per-spec diagnosis enabled (calico-mcp: on)" \
  "SANDCAT_INLINE_GEMINI_KEY=key-a" \
  "SANDCAT_INLINE_BIN=" "SANDCAT_INLINE_CALICO_MCP_BIN=" "SANDCAT_INLINE_PR_CONTEXT=" \
  "SANDCAT_SIG_DIR=/tmp/sandcat-sigs" "SANDCAT_MAX_DIAGNOSES=10" "SANDCAT_TOTAL_BUDGET=25m"

# A job may carry gemini-api-key without sandcat-nightly.
newhome
export GEMINI_API_KEY=key-b
check "GEMINI_API_KEY is accepted too" 0 "SANDCAT_INLINE_GEMINI_KEY=key-b" "calico-mcp: on"

newhome
export SANDCAT_GEMINI_KEY=key-a STUB_MCP_RC=3
check "probe says calico-mcp is unusable: refuse" 1 \
  "calico-mcp unavailable" "could not wire it to the cluster" \
  '!inline per-spec diagnosis enabled'

# Other non-zero codes may come from an old sandcat without check-mcp.
newhome
export SANDCAT_GEMINI_KEY=key-a STUB_MCP_RC=1
check "ambiguous probe result: still enabled" 0 "calico-mcp: on"

newhome
export SANDCAT_GEMINI_KEY=key-a SANDCAT_CALICO_MCP=0
check "SANDCAT_CALICO_MCP=0 is a real off switch" 0 \
  "calico-mcp: off" "SANDCAT_INLINE_CALICO_MCP_BIN=''"

# Shadow gcloud with a failing stub so no real `gcloud storage cp` can run.
newhome
export SANDCAT_GEMINI_KEY=key-a
rm -f "${CALICO_MCP_LOCAL_BIN}"
printf '#!/bin/sh\necho "stub gcloud: refusing" >&2\nexit 1\n' > "${HOME}/.local/bin/gcloud"
chmod +x "${HOME}/.local/bin/gcloud"
export PATH="${HOME}/.local/bin:${PATH}"
export CALICO_MCP_BUCKET=gs://sandcat-test-no-such-bucket
check "calico-mcp cannot be fetched: refuse" 1 \
  "calico-mcp unavailable" "download or its --version check failed"
unset CALICO_MCP_BUCKET

newhome
export SANDCAT_GEMINI_KEY=key-a STUB_PR=0
check "branch run: no PR context, still enabled" 0 \
  "SANDCAT_INLINE_PR_CONTEXT=''" "calico-mcp: on"

# The sig dir is fixed because the banzai lane injects it into the run container.
newhome
export SANDCAT_GEMINI_KEY=key-a SANDCAT_MAX_DIAGNOSES=3 SANDCAT_TOTAL_BUDGET=5m SANDCAT_SIG_DIR=/tmp/from-the-environment
check "budget knobs pass through, sig dir stays fixed" 0 \
  "SANDCAT_MAX_DIAGNOSES=3" "SANDCAT_TOTAL_BUDGET=5m" \
  "SANDCAT_SIG_DIR=/tmp/sandcat-sigs" '!/tmp/from-the-environment' 

# A leftover file would have the epilogue's analyze blame an earlier job's PR.
newhome
export SANDCAT_GEMINI_KEY=key-a STUB_MCP_RC=3
echo '{"body":"a previous job'"'"'s PR"}' > "${SANDCAT_PR_CONTEXT_FILE}"
"${SCRIPT}" inline-env --kubeconfig /tmp/kubeconfig >/dev/null 2>&1
if [[ -e "${SANDCAT_PR_CONTEXT_FILE}" ]]; then
  echo "FAIL refusal leaves a previous job's PR context behind"
  fail=$((fail + 1))
else
  echo "PASS refusal clears a previous job's PR context"
  pass=$((pass + 1))
fi

newhome
export SANDCAT_GEMINI_KEY=key-a SANDCAT_DB_URL=postgres://broker SANDCAT_DB_TOKEN=t
check "metrics reported as enabled" 0 "metrics enabled (postgres://broker)"
unset SANDCAT_DB_URL SANDCAT_DB_TOKEN

newhome
export SANDCAT_GEMINI_KEY=key-a SANDCAT_DB_URL=postgres://broker
check "metrics reported as off, naming what was missing" 0 \
  "metrics off" "did not provide SANDCAT_DB_TOKEN" '!did not provide SANDCAT_DB_URL'
unset SANDCAT_DB_URL

# The secret's state is reported even when calico-mcp is refused.
newhome
export SANDCAT_GEMINI_KEY=key-a STUB_MCP_RC=3 SANDCAT_DB_URL=postgres://broker SANDCAT_DB_TOKEN=t
check "metrics still reported when calico-mcp is refused" 1 \
  "metrics enabled (postgres://broker)" "calico-mcp unavailable"
unset SANDCAT_DB_URL SANDCAT_DB_TOKEN

# A calico-mcp that outlives check-mcp must not hold the caller's $( ) open.
newhome
export SANDCAT_GEMINI_KEY=key-a
cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  check-mcp)
    # An orphan that outlives us, as a wedged calico-mcp server would. It
    # reaps itself well after the probe is timed out below -- long enough to
    # block a caller that still shares its pipe, short enough to leave nothing
    # behind on an agent.
    sleep 30 &
    exit 0
    ;;
  fetch-pr)
    out=""
    while [[ $# -gt 0 ]]; do
      [[ "$1" == "--out" ]] && out="$2"
      shift
    done
    echo '{"body":"stub"}' > "${out}"
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "${HOME}/.local/bin/sandcat"
# Captured with $( ) as the callers do: the pipe is what an orphan would hold.
_start=${SECONDS}
if timeout 20 bash -c 'payload=$("$0" inline-env --kubeconfig /tmp/kubeconfig 2>/dev/null); [[ -n "${payload}" ]]' "${SCRIPT}"; then
  echo "PASS an orphaned probe child does not hold the payload pipe open ($((SECONDS - _start))s)"
  pass=$((pass + 1))
else
  echo "FAIL an orphaned probe child held the payload pipe open"
  fail=$((fail + 1))
fi
echo "=== ${pass} passed, ${fail} failed"
[[ "${fail}" == 0 ]]
