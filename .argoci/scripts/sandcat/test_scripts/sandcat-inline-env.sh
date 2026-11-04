#!/usr/bin/env bash
# Behaviour test for `sandcat.sh inline-env` -- the decision shared by the two
# callers that wire up the inline per-spec failure hook (run_tests.sh, which
# bind-mounts into the e2e run container, and with-inline-diag.sh, which runs
# ginkgo on the host).
#
# What is worth pinning here is the refusals. Every one of them is a case where
# running the hook anyway is worse than not running it: a diagnosis without the
# live-cluster tools spends the model budget and returns a verdict that looks
# like every other verdict, and a silent skip is indistinguishable in the job
# log from "analysed and found nothing".
#
# sandcat and calico-mcp are stubbed, so this needs no network, no cluster and
# no Gemini key.

set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandcat.sh}"
ORIGINAL_PATH="${PATH}"

# Every key the payload may carry, and no others. The callers eval this stream,
# so the set is a contract, not an implementation detail.
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
pass=0
fail=0

# check <name> <want_rc> [pattern...] -- a pattern prefixed with ! must NOT appear.
#
# The two streams are captured separately, and every stdout line is required to
# be a KEY=VALUE assignment. That is the one load-bearing contract here: both
# callers eval this stdout, so a stray log line on it is executed as shell and
# takes the job down instead of degrading to "no diagnosis". Merging the streams
# (2>&1) would make a payload written to stderr and a message written to stdout
# indistinguishable, which is exactly the defect worth catching.
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
    # Assignment-shaped is not enough: both callers eval this, so a leak that
    # happens to look like one -- `PATH=...` from some future subcommand -- would
    # corrupt the caller's environment rather than fail here.
    if [[ " ${PAYLOAD_KEYS[*]} " != *" ${line%%=*} "* ]]; then
      ok=0
      echo "  unexpected key on stdout: ${line%%=*}"
    fi
    keys+=("${line%%=*}")
  done <<<"${out}"
  # ...and the payload has to be on stdout in the first place. Asserting the
  # keys against the merged streams below would pass just as happily if every
  # one of them had gone to stderr, where the callers never see them -- which
  # is the same defect as a log line on stdout, in the other direction.
  if [[ "${want_rc}" == 0 && "${#keys[@]}" != "${#PAYLOAD_KEYS[@]}" ]]; then
    ok=0
    echo "  stdout carried ${#keys[@]} of ${#PAYLOAD_KEYS[@]} payload keys"
  fi
  # A refusal must print nothing at all on stdout: the callers only skip the
  # eval when the exit code says so, and a half-written payload is worse than
  # none.
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

# A fresh HOME per case: sandcat.sh caches both binaries under it and skips a
# download when the file is already there, so cases would otherwise leak into
# each other.
newhome() {
  HOME=$(mktemp -d)
  export HOME
  mkdir -p "${HOME}/.local/bin"
  # The stub answers only what inline-env asks of it. STUB_MCP_RC drives the
  # check-mcp probe's exit code (3 is sandcat's "calico-mcp unavailable");
  # STUB_PR=0 is a branch run, where fetch-pr writes nothing and exits non-zero.
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
  # Restored per case: the download-failure case below shadows gcloud, and a
  # leak into a later case would have it silently exercise a real download.
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

# Any other non-zero is ambiguous -- notably what a sandcat release predating
# check-mcp returns for an unknown subcommand -- so it must not disable anything.
newhome
export SANDCAT_GEMINI_KEY=key-a STUB_MCP_RC=1
check "ambiguous probe result: still enabled" 0 "calico-mcp: on"

newhome
export SANDCAT_GEMINI_KEY=key-a SANDCAT_CALICO_MCP=0
check "SANDCAT_CALICO_MCP=0 is a real off switch" 0 \
  "calico-mcp: off" "SANDCAT_INLINE_CALICO_MCP_BIN=''"

# Shadow gcloud with one that fails, rather than removing it from PATH: this
# has to fail without touching the network, and prepending a directory that
# does not exist would leave the real gcloud resolvable and run a real
# `gcloud storage cp` against the bucket.
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

# The budget is a per-job knob, but the coordination dir is not: the banzai
# lane injects this value into the run container, so a host path taken from the
# environment would name somewhere that is not mounted there.
newhome
export SANDCAT_GEMINI_KEY=key-a SANDCAT_MAX_DIAGNOSES=3 SANDCAT_TOTAL_BUDGET=5m SANDCAT_SIG_DIR=/tmp/from-the-environment
check "budget knobs pass through, sig dir stays fixed" 0 \
  "SANDCAT_MAX_DIAGNOSES=3" "SANDCAT_TOTAL_BUDGET=5m" \
  "SANDCAT_SIG_DIR=/tmp/sandcat-sigs" '!/tmp/from-the-environment' 

# The epilogue's `analyze` reads the same path, so a file left by an earlier job
# on an agent with a reused home would have the run-level analysis reason about
# -- and blame -- the wrong PR. Clearing it has to survive every refusal, which
# is why it happens before the first one rather than as part of the fetch.
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

# An un-enabled Semaphore secret injects nothing and says nothing, so this line
# is the only evidence either way.
newhome
export SANDCAT_GEMINI_KEY=key-a SANDCAT_DB_URL=postgres://broker SANDCAT_DB_TOKEN=t
check "metrics reported as enabled" 0 "metrics enabled (postgres://broker)"
unset SANDCAT_DB_URL SANDCAT_DB_TOKEN

newhome
export SANDCAT_GEMINI_KEY=key-a SANDCAT_DB_URL=postgres://broker
check "metrics reported as off, naming what was missing" 0 \
  "metrics off" "did not provide SANDCAT_DB_TOKEN" '!did not provide SANDCAT_DB_URL'
unset SANDCAT_DB_URL

# The refusals are exactly when someone reads the log, so the secret's state has
# to be reported before anything can return early -- not alongside the payload.
newhome
export SANDCAT_GEMINI_KEY=key-a STUB_MCP_RC=3 SANDCAT_DB_URL=postgres://broker SANDCAT_DB_TOKEN=t
check "metrics still reported when calico-mcp is refused" 1 \
  "metrics enabled (postgres://broker)" "calico-mcp unavailable"
unset SANDCAT_DB_URL SANDCAT_DB_TOKEN

# The probe spawns a server and talks to the cluster, and this whole function
# runs inside the caller's `$( )`. A calico-mcp that outlives check-mcp while
# holding the payload pipe would stall the caller for as long as it lives --
# on the KinD lane, between kind-up and the suite, that is the pipeline limit
# with zero tests run. fd 3 is closed for the probe, so it cannot.
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
# Captured, the way both callers do it: the exposure is the substitution's pipe,
# so redirecting to a file here would test nothing -- fd 3 would be that file
# and an orphan holding it would block no one.
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
