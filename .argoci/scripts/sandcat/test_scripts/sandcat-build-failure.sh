#!/usr/bin/env bash
# Behaviour test for `sandcat.sh build-failure`: which log it picks and whether
# it can read it. sandcat is stubbed, so no binary, network or cluster is needed.

set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandcat.sh}"
REPO_ROOT="$(cd "$(dirname "${SCRIPT}")/../../.." && pwd)"
pass=0
fail=0

# The stub records the --log-file it was handed and that file's content.
newhome() {
  HOME=$(mktemp -d)
  export HOME
  mkdir -p "${HOME}/.local/bin" "${HOME}/bin" "${HOME}/logs" "${HOME}/tmp" "${HOME}/work"
  LOGS_DIR="${HOME}/logs"
  SEEN="${HOME}/seen"
  # Expansions land here, so a leaked one is visible and the real /tmp untouched.
  TMPDIR="${HOME}/tmp"
  export LOGS_DIR SEEN TMPDIR
  cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
lf="" bf=""
while [[ $# -gt 0 ]]; do
  [[ "$1" == "--log-file" ]] && lf="$2"
  [[ "$1" == "--build-failure" ]] && bf=yes
  shift
done
{
  echo "BUILD_FAILURE=${bf}"
  echo "LOG_FILE=${lf}"
  echo "FIRST_LINE=$(head -n1 "${lf}" 2>/dev/null)"
  echo "LAST_LINE=$(tail -n1 "${lf}" 2>/dev/null)"
  echo "SIZE=$(stat -c %s "${lf}" 2>/dev/null || echo -1)"
  # A marker in the middle of the log is invisible to the first/last line pair,
  # and the elision notice is by definition in the middle.
  sed -n 's/^\(\[sandcat\].*\)$/MARKER=\1/p' "${lf}" 2>/dev/null
} >> "${SEEN}"
[[ -n "${lf}" && "${STUB_LOG_FAIL:-}" == 1 ]] && exit 1
exit 0
STUB
  chmod +x "${HOME}/.local/bin/sandcat"
  # Keeps `artifact push` from publishing to a real job.
  cat > "${HOME}/bin/artifact" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x "${HOME}/bin/artifact"
  PATH="${HOME}/bin:${PATH}"
  export PATH
  # Required to pass the upload gate; port 9 refuses the upload locally.
  export SANDCAT_INGEST_TOKEN=t SANDCAT_UPLOAD_URL=http://127.0.0.1:9/ignored
  unset STUB_LOG_FAIL
}

# Explicit mtimes, so "newest" does not depend on test timing.
age() {
  touch -d "2020-01-01 00:00:${2}" "$1"
}

# run <name> [args...] -- invoke build-failure from a scratch dir, where analyze
# writes its run record.
run() {
  local name="$1"
  shift
  rm -f "${SEEN}"
  OUTPUT=$(cd "${HOME}/work" && "${SCRIPT}" build-failure --source-dir "${REPO_ROOT}" "$@" 2>&1) || true
  RESULT=""
  [[ -f "${SEEN}" ]] && RESULT=$(cat "${SEEN}")
  CASE="${name}"
}

# run_analyze <name> [args...] -- the analyze path, which shares the expansion.
run_analyze() {
  local name="$1"
  shift
  rm -f "${SEEN}"
  OUTPUT=$(cd "${HOME}/work" && SANDCAT_CALICO_MCP=0 \
    "${SCRIPT}" analyze --source-dir "${REPO_ROOT}" "$@" 2>&1) || true
  RESULT=""
  [[ -f "${SEEN}" ]] && RESULT=$(cat "${SEEN}")
  CASE="${name}"
}

# expect <pattern>... -- a pattern prefixed with ! must NOT appear. Also searches
# the script output, the only place the chosen and skipped logs are named.
expect() {
  local ok=1 pat haystack
  haystack="${RESULT}"$'\n'"${OUTPUT}"
  for pat in "$@"; do
    if [[ "${pat}" == '!'* ]]; then
      grep -qF -- "${pat#!}" <<<"${haystack}" && { ok=0; echo "  unexpected: ${pat#!}"; }
    elif ! grep -qF -- "${pat}" <<<"${haystack}"; then
      ok=0
      echo "  missing: ${pat}"
    fi
  done
  if [[ "${ok}" == 1 ]]; then
    echo "PASS ${CASE}"
    pass=$((pass + 1))
  else
    echo "FAIL ${CASE}"
    sed 's/^/    /' <<<"${RESULT:-<sandcat was never invoked>}"
    fail=$((fail + 1))
  fi
}

# expect_max_size <bytes> -- the cap marker alone does not prove the write stopped.
expect_max_size() {
  local limit="$1" size
  size=$(sed -n 's/^SIZE=//p' <<<"${RESULT}")
  if [[ -n "${size}" && "${size}" -ge 0 && "${size}" -le "${limit}" ]]; then
    echo "PASS ${CASE} (bounded at ${size} bytes)"
    pass=$((pass + 1))
  else
    echo "FAIL ${CASE} (expanded to ${size:-<nothing>} bytes, limit ${limit})"
    fail=$((fail + 1))
  fi
}

# expect_no_expansion_left -- the expanded copy must not outlive the run.
expect_no_expansion_left() {
  local left
  left=$(find "${TMPDIR}" -maxdepth 1 -name 'sandcat-build-log.*' 2>/dev/null)
  if [[ -z "${left}" ]]; then
    echo "PASS ${CASE} (no expansion left behind)"
    pass=$((pass + 1))
  else
    echo "FAIL ${CASE} (expansion left behind: ${left})"
    fail=$((fail + 1))
  fi
}

# A setup failure on the standard lane, where every candidate is gzipped.
newhome
echo "provisioning the cluster" | gzip > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 01
echo "error: timed out waiting on tigerastatus/apiserver" | gzip > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 02
run "gzipped setup logs: newest is picked and expanded" --logs-dir "${LOGS_DIR}"
# sandcat is handed the expanded copy, never the .gz it cannot read.
expect "FIRST_LINE=error: timed out waiting on tigerastatus/apiserver" \
  "!LOG_FILE=${LOGS_DIR}/install.log.gz"
expect_no_expansion_left

# The epilogue writes these itself, after the failure.
newhome
echo "the real failure" | gzip > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 01
echo "collecting diags" > "${LOGS_DIR}/diagnostic.log"; age "${LOGS_DIR}/diagnostic.log" 02
echo "destroying the cluster" > "${LOGS_DIR}/destroy.log"; age "${LOGS_DIR}/destroy.log" 03
run "the epilogue's own logs are not candidates" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=the real failure"

# The HCP lane and the local e2e runner write theirs uncompressed.
newhome
echo "plain hcp provision output" > "${LOGS_DIR}/provision.log"
run "a plain log is used as it is" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=plain hcp provision output" "LOG_FILE=${LOGS_DIR}/provision.log"

newhome
echo "older, compressed" | gzip > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 01
echo "newer, plain" > "${LOGS_DIR}/upgrade.log"; age "${LOGS_DIR}/upgrade.log" 02
run "newest wins across both kinds" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=newer, plain"

# A job killed mid-phase leaves a truncated gzip whose prefix is still useful.
newhome
{ echo "phase started"; echo "the last thing before the kill"; } | gzip > "${LOGS_DIR}/install.log.gz"
truncate -s -20 "${LOGS_DIR}/install.log.gz"
run "a truncated gzip is salvaged, and says so" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=phase started" "LAST_LINE=[sandcat] this log is incomplete"

# A marker-only temp file would be analyzed as if it were a log.
newhome
echo "never made it to disk" | gzip > "${LOGS_DIR}/install.log.gz"
truncate -s 10 "${LOGS_DIR}/install.log.gz"
run "a gzip that recovers nothing: recorded without a log" --logs-dir "${LOGS_DIR}"
expect "BUILD_FAILURE=yes" "!LOG_FILE=/"

# Left by a phase killed the instant `tee` created its file.
newhome
: > "${LOGS_DIR}/install.log"
run "an empty plain log: recorded without a log" --logs-dir "${LOGS_DIR}"
expect "BUILD_FAILURE=yes" "!LOG_FILE=/"

# sandcat anchors on the end of the log, so the bound keeps both ends.
newhome
SANDCAT_MAX_LOG_BYTES=2048 && export SANDCAT_MAX_LOG_BYTES
{ echo "first line of a very long log"
  head -c 65536 /dev/zero | tr '\0' 'x'
  echo
  echo "error: the thing that actually broke"; } \
  | gzip > "${LOGS_DIR}/k8s-e2e-tests.log.gz"
run "an oversized expansion keeps both ends, and says so" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=first line of a very long log" \
  "LAST_LINE=error: the thing that actually broke" \
  "the middle of this log was skipped"
# 64 KiB went in; the cap plus the marker line is what may come out.
expect_max_size 2304

expect "!LAST_LINE=xxx"
unset SANDCAT_MAX_LOG_BYTES

newhome
SANDCAT_MAX_LOG_BYTES=2048 && export SANDCAT_MAX_LOG_BYTES
{ echo "first line of a very long log"; head -c 65536 /dev/zero | tr '\0' 'x'; } \
  | gzip > "${LOGS_DIR}/k8s-e2e-tests.log.gz"
truncate -s -20 "${LOGS_DIR}/k8s-e2e-tests.log.gz"
run "oversized and truncated: both are reported" --logs-dir "${LOGS_DIR}"
expect "the middle of this log was skipped" \
  "LAST_LINE=[sandcat] this log is incomplete"
unset SANDCAT_MAX_LOG_BYTES

# Newest by mtime, not by glob order.
newhome
echo "error: the newest phase" | gzip > "${LOGS_DIR}/upgrade.log.gz"; age "${LOGS_DIR}/upgrade.log.gz" 02
echo "an earlier phase that sorts first" | gzip > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 01
run "newest is by mtime, not by glob order" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: the newest phase"

# A phase killed before gzip flushes leaves an empty newest .gz; the log of the
# phase before it must still be used.
newhome
echo "error: provisioning never finished" | gzip > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 01
: > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 02
run "an empty newest log falls back to the phase before it" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: provisioning never finished" \
  "install.log.gz holds nothing readable"

# The same for a gzip header with nothing recoverable behind it.
newhome
echo "error: provisioning never finished" | gzip > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 01
echo "never made it to disk" | gzip > "${LOGS_DIR}/install.log.gz"
truncate -s 10 "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 02
run "an unrecoverable newest log falls back too" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: provisioning never finished"

# Two dead phases in a row, as a job killed in a retry loop leaves.
newhome
echo "error: the first phase" | gzip > "${LOGS_DIR}/initialize.log.gz"; age "${LOGS_DIR}/initialize.log.gz" 01
: > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 02
: > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 03
run "the fallback keeps walking past more than one dead log" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: the first phase"

newhome
: > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 01
: > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 02
run "all candidates empty: recorded without a log" --logs-dir "${LOGS_DIR}"
expect "BUILD_FAILURE=yes" "!LOG_FILE=/"

# Paths must survive a directory name with a space in it.
newhome
SPACED="${HOME}/logs with space"
mkdir -p "${SPACED}"
echo "an earlier phase" | gzip > "${SPACED}/provision.log.gz"; age "${SPACED}/provision.log.gz" 01
echo "error: the newest phase" | gzip > "${SPACED}/install.log.gz"; age "${SPACED}/install.log.gz" 02
run "a logs dir with a space in it still picks the newest" --logs-dir "${SPACED}"
expect "FIRST_LINE=error: the newest phase"

newhome
SPACED="${HOME}/logs with space"
mkdir -p "${SPACED}"
echo "error: an earlier phase" | gzip > "${SPACED}/provision.log.gz"; age "${SPACED}/provision.log.gz" 01
: > "${SPACED}/install.log.gz"; age "${SPACED}/install.log.gz" 02
run "a logs dir with a space in it still falls back" --logs-dir "${SPACED}"
expect "FIRST_LINE=error: an earlier phase"

newhome
echo "not this one" > "${LOGS_DIR}/provision.log"
echo "this one" > "${HOME}/explicit.log"
run "an explicit --log-file wins over the directory" \
  --log-file "${HOME}/explicit.log" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=this one"

newhome
run "no logs at all: recorded without a log" --logs-dir "${LOGS_DIR}"
expect "BUILD_FAILURE=yes" "!LOG_FILE=/"

newhome
run "no directory and no file: recorded without a log"
expect "BUILD_FAILURE=yes" "!LOG_FILE=/"

newhome
echo "error: install failed" > "${LOGS_DIR}/install.log"
export STUB_LOG_FAIL=1
run "a failed log analysis: the failure is recorded without the log" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: install failed" "BUILD_FAILURE=yes" "log analysis failed"

newhome
echo '{}' > "${HOME}/report.json"
echo "the tail of the test run" | gzip > "${LOGS_DIR}/k8s-e2e-tests.log.gz"
run_analyze "analyze expands a gzipped --log-file too" \
  --report "${HOME}/report.json" --log-file "${LOGS_DIR}/k8s-e2e-tests.log.gz"
expect "FIRST_LINE=the tail of the test run" "!LOG_FILE=${LOGS_DIR}/k8s-e2e-tests.log.gz"
expect_no_expansion_left

newhome
echo '{}' > "${HOME}/report.json"
echo "plain as it comes" > "${LOGS_DIR}/k8s-e2e-tests.log"
run_analyze "analyze passes a plain --log-file straight through" \
  --report "${HOME}/report.json" --log-file "${LOGS_DIR}/k8s-e2e-tests.log"
expect "LOG_FILE=${LOGS_DIR}/k8s-e2e-tests.log" "FIRST_LINE=plain as it comes"

echo "=== ${pass} passed, ${fail} failed"
[[ "${fail}" == 0 ]]
