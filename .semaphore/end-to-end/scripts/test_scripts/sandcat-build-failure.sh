#!/usr/bin/env bash
# Behaviour test for `sandcat.sh build-failure`: which log it reads, and whether
# it can read it at all.
#
# This is the path for a job that died before its tests ran, so the log it picks
# is the only account of what happened. When it cannot read one, the synthetic
# record it falls back to says "Build/setup failed before tests could run",
# which is true and says nothing -- so the cases below pin both halves: that the
# right log is picked and expanded, and that nothing which is not a log reaches
# the analyzer dressed up as one.
#
# sandcat is stubbed, so no binary, network or cluster is needed. What is
# asserted is the argument sandcat is handed and the content behind it.

set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandcat.sh}"
REPO_ROOT="$(cd "$(dirname "${SCRIPT}")/../../.." && pwd)"
pass=0
fail=0

# The stub records the --log-file it was given and that file's first line, which
# is what distinguishes "picked the right log" from "picked a log".
newhome() {
  HOME=$(mktemp -d)
  export HOME
  mkdir -p "${HOME}/.local/bin" "${HOME}/bin" "${HOME}/logs" "${HOME}/tmp" "${HOME}/work"
  LOGS_DIR="${HOME}/logs"
  SEEN="${HOME}/seen"
  # Expansions land here rather than in the real /tmp, so a case that leaks one
  # is visible and the machine running the test is left alone.
  TMPDIR="${HOME}/tmp"
  export LOGS_DIR SEEN TMPDIR
  cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
lf=""
while [[ $# -gt 0 ]]; do
  [[ "$1" == "--log-file" ]] && lf="$2"
  shift
done
{
  echo "LOG_FILE=${lf}"
  echo "FIRST_LINE=$(head -n1 "${lf}" 2>/dev/null)"
  echo "LAST_LINE=$(tail -n1 "${lf}" 2>/dev/null)"
  echo "SIZE=$(stat -c %s "${lf}" 2>/dev/null || echo -1)"
  # A marker in the middle of the log is invisible to the first/last line pair,
  # and the elision notice is by definition in the middle.
  sed -n 's/^\(\[sandcat\].*\)$/MARKER=\1/p' "${lf}" 2>/dev/null
} > "${SEEN}"
STUB
  chmod +x "${HOME}/.local/bin/sandcat"
  # The cases that end in the synthetic record run its real tail, which pushes a
  # job artifact when the toolbox CLI is on PATH. On a Semaphore agent it is, so
  # without this shim a passing validation run would publish a fabricated
  # build-failure record -- carrying this job's real SHA and author -- as
  # semaphore/sandcat-analysis.json.
  cat > "${HOME}/bin/artifact" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x "${HOME}/bin/artifact"
  PATH="${HOME}/bin:${PATH}"
  export PATH
  # build-failure runs behind the upload gate, so these have to be present for
  # the subcommand to be reached at all. Port 9 is discard: the upload fails on
  # connection refused without leaving the machine.
  export SANDCAT_INGEST_TOKEN=t SANDCAT_UPLOAD_URL=http://127.0.0.1:9/ignored
}

# Give a file an explicit mtime, so "newest" is decided by the test rather than
# by how long the case took to run.
age() {
  touch -d "2020-01-01 00:00:${2}" "$1"
}

# run <name> [args...] -- invoke build-failure and report what sandcat was given.
# Run from a scratch directory: the synthetic path writes its record into the
# working directory, which must not be the checkout.
run() {
  local name="$1"
  shift
  rm -f "${SEEN}"
  OUTPUT=$(cd "${HOME}/work" && "${SCRIPT}" build-failure --source-dir "${REPO_ROOT}" "$@" 2>&1) || true
  RESULT=""
  [[ -f "${SEEN}" ]] && RESULT=$(cat "${SEEN}")
  CASE="${name}"
}

# run_analyze <name> [args...] -- the per-run path, which shares the expansion
# helper with build-failure. SANDCAT_CALICO_MCP=0 keeps it from trying to fetch
# a second binary it would then refuse to run without.
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

# expect <pattern>... -- a pattern prefixed with ! must NOT appear. Searches both
# what sandcat was handed and what the script printed on the way to handing it
# over: which log it chose, and which it skipped to get there, are only ever said
# out loud.
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

# expect_max_size <bytes> -- the log handed to sandcat must be no bigger than
# this. The cap marker alone does not prove a bound: it is appended whenever the
# expansion reached the ceiling, whether or not the write was stopped there.
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

# expect_no_expansion_left -- the expanded copy is this script's, and it is the
# only thing it writes to the agent's disk, so nothing of it may outlive the run.
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

# The epilogue writes both of these itself, after the failure, and they describe
# teardown rather than what went wrong.
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

# `tee >(gzip --stdout > ...)` leaves a truncated stream when a job is killed
# mid-phase. What it wrote before that is usually the whole story.
newhome
{ echo "phase started"; echo "the last thing before the kill"; } | gzip > "${LOGS_DIR}/install.log.gz"
truncate -s -20 "${LOGS_DIR}/install.log.gz"
run "a truncated gzip is salvaged, and says so" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=phase started" "LAST_LINE=[sandcat] this log is incomplete"

# Salvage stops where the evidence does. A header-only .gz yields no bytes at
# all, and a temp file holding nothing but the marker is a sentence this script
# wrote about a log it never read -- it must not be analyzed as if it were one.
newhome
echo "never made it to disk" | gzip > "${LOGS_DIR}/install.log.gz"
truncate -s 10 "${LOGS_DIR}/install.log.gz"
run "a gzip that recovers nothing: sandcat is not invoked" --logs-dir "${LOGS_DIR}"
expect "!LOG_FILE="

# The same outcome for a plain log with nothing in it, which is what a phase
# killed the instant `tee` created its file leaves behind.
newhome
: > "${LOGS_DIR}/install.log"
run "an empty plain log: sandcat is not invoked" --logs-dir "${LOGS_DIR}"
expect "!LOG_FILE="

# The expansion is the only thing this script writes to the agent's disk, so it
# is the only thing it has to bound. A whole compressed test run is the case
# that makes this matter.
#
# What survives the bound is the point. A failure is the last thing a phase
# writes, and sandcat anchors on the end of the log, so keeping only the opening
# would hand it the middle of a run to read as the failure. Both ends are kept
# and the middle is dropped.
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

# The head on its own is not enough, and this is the case that says so: with the
# cap smaller than the run, the error at the end is reachable only because the
# tail is kept.
expect "!LAST_LINE=xxx"
unset SANDCAT_MAX_LOG_BYTES

# A log both past the ceiling and unreadable to the end: the tail is the tail of
# what could be recovered, not of the log, and it has to say so rather than let
# the last recovered line read as the last thing that happened.
newhome
SANDCAT_MAX_LOG_BYTES=2048 && export SANDCAT_MAX_LOG_BYTES
{ echo "first line of a very long log"; head -c 65536 /dev/zero | tr '\0' 'x'; } \
  | gzip > "${LOGS_DIR}/k8s-e2e-tests.log.gz"
truncate -s -20 "${LOGS_DIR}/k8s-e2e-tests.log.gz"
run "oversized and truncated: both are reported" --logs-dir "${LOGS_DIR}"
expect "the middle of this log was skipped" \
  "LAST_LINE=[sandcat] this log is incomplete"
unset SANDCAT_MAX_LOG_BYTES

# Newest by mtime, not by the order the globs happen to expand in. The two agree
# in most of these cases -- install.log.gz sorts after provision.log.gz and is
# also written after it -- so this pairs a phase that sorts first with a later
# one that does not, where taking the list as it comes would pick the wrong log.
newhome
echo "error: the newest phase" | gzip > "${LOGS_DIR}/upgrade.log.gz"; age "${LOGS_DIR}/upgrade.log.gz" 02
echo "an earlier phase that sorts first" | gzip > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 01
run "newest is by mtime, not by glob order" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: the newest phase"

# `tee >(gzip --stdout > install.log.gz)` creates the file the instant the phase
# starts, but gzip buffers ~32 KiB before flushing, so a phase killed under that
# leaves a zero-byte install.log.gz -- the newest file in the directory, and
# empty. Committing to the newest name would discard the populated log of the
# phase before it, on exactly the killed-mid-setup failure this path exists for.
newhome
echo "error: provisioning never finished" | gzip > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 01
: > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 02
run "an empty newest log falls back to the phase before it" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: provisioning never finished" \
  "install.log.gz holds nothing readable"

# The same when the newest is a gzip header with no recoverable content behind
# it, which is the other shape a killed phase leaves.
newhome
echo "error: provisioning never finished" | gzip > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 01
echo "never made it to disk" | gzip > "${LOGS_DIR}/install.log.gz"
truncate -s 10 "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 02
run "an unrecoverable newest log falls back too" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: provisioning never finished"

# The fallback walks, it does not stop at the second: two dead phases in a row
# is what a job killed during a retry loop leaves behind.
newhome
echo "error: the first phase" | gzip > "${LOGS_DIR}/initialize.log.gz"; age "${LOGS_DIR}/initialize.log.gz" 01
: > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 02
: > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 03
run "the fallback keeps walking past more than one dead log" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=error: the first phase"

# Every candidate empty is still "nothing to read", not a record invented from
# the last name in the list.
newhome
: > "${LOGS_DIR}/provision.log.gz"; age "${LOGS_DIR}/provision.log.gz" 01
: > "${LOGS_DIR}/install.log.gz"; age "${LOGS_DIR}/install.log.gz" 02
run "all candidates empty: sandcat is not invoked" --logs-dir "${LOGS_DIR}"
expect "!LOG_FILE="

# Paths are carried through the walk as array elements, never as a split string,
# so a directory with a space in it selects the same log as one without. The
# fixtures all live under a path with no spaces, so nothing else here would
# notice if that stopped being true.
newhome
SPACED="${HOME}/logs with space"
mkdir -p "${SPACED}"
echo "an earlier phase" | gzip > "${SPACED}/provision.log.gz"; age "${SPACED}/provision.log.gz" 01
echo "error: the newest phase" | gzip > "${SPACED}/install.log.gz"; age "${SPACED}/install.log.gz" 02
run "a logs dir with a space in it still picks the newest" --logs-dir "${SPACED}"
expect "FIRST_LINE=error: the newest phase"

# And the fallback still walks it, which is the path that rebuilds the candidate
# list on every step.
newhome
SPACED="${HOME}/logs with space"
mkdir -p "${SPACED}"
echo "error: an earlier phase" | gzip > "${SPACED}/provision.log.gz"; age "${SPACED}/provision.log.gz" 01
: > "${SPACED}/install.log.gz"; age "${SPACED}/install.log.gz" 02
run "a logs dir with a space in it still falls back" --logs-dir "${SPACED}"
expect "FIRST_LINE=error: an earlier phase"

# The caller that knows which log it wants still names it.
newhome
echo "not this one" > "${LOGS_DIR}/provision.log"
echo "this one" > "${HOME}/explicit.log"
run "an explicit --log-file wins over the directory" \
  --log-file "${HOME}/explicit.log" --logs-dir "${LOGS_DIR}"
expect "FIRST_LINE=this one"

# Nothing to read is still a legitimate outcome -- it just must not pretend to
# have analyzed one.
newhome
run "no logs at all: sandcat is not invoked" --logs-dir "${LOGS_DIR}"
expect "!LOG_FILE="

newhome
run "no directory and no file: sandcat is not invoked"
expect "!LOG_FILE="

# `analyze` reads --log-file the same way the binary does, so it needs the same
# sniff. Today every caller hands it a plain log; the point is that the day one
# of them is harmonised with the phases that gzip theirs, nothing here has to
# notice.
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
