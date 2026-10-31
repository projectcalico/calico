#!/usr/bin/env bash
# Shared sandcat helper — single source of truth for downloading and invoking
# the sandcat AI failure analyzer. Called from run_tests.sh and
# with-inline-diag.sh (in-test, with live cluster), global_epilogue.sh
# (fallback when run_tests.sh didn't run), and the KinD e2e epilogue block in
# 20-e2e.yml.
#
# Coordination: run_tests.sh touches ~/.sandcat-analyzed after a successful run
# so that global_epilogue.sh skips re-analysis. If run_tests.sh never ran (or
# skipped sandcat because no report existed), the marker is absent and the
# epilogue path picks it up.
#
# Usage:
#   sandcat.sh analyze [OPTIONS]   — download binary, run analysis, upload
#     --spec-dir DIR                — where the inline per-spec diagnoses were
#                                     written; only needed when the report is
#                                     not a sibling of that directory
#   sandcat.sh build-failure       — analyze the job log; synthetic record fallback
#     --log-file FILE               the log to read, gzipped or not
#     --logs-dir DIR                where the phases wrote theirs, to pick from
#                                   when the caller cannot name one
#   sandcat.sh push-specs          — push the inline per-spec diagnoses as one
#     --spec-dir DIR                artifact; the report names the directory
#     --report FILE                 when --spec-dir is absent
#   sandcat.sh download            — fetch the binary, print its path
#   sandcat.sh fetch-pr            — fetch the PR context file, print its path
#   sandcat.sh download-calico-mcp — fetch calico-mcp, print its path
#   sandcat.sh inline-env          — resolve the inline per-spec failure hook's
#     --kubeconfig PATH             setup and print it as KEY=VALUE lines to
#     --source-dir DIR              eval; non-zero means "do not run the hook"
#
# Required env vars (gated — exits silently when absent):
#   SANDCAT_INGEST_TOKEN, SANDCAT_UPLOAD_URL
# Optional:
#   SANDCAT_CALICO_MCP=0 — diagnose without calico-mcp's live-cluster tools
#   CALICO_MCP_VERSION    — pin a calico-mcp build (default: dev-latest)
# Required for `analyze` only (binary download from the private release):
#   GITHUB_ACCESS_TOKEN
#
# All failures are non-fatal: the entire script runs in a subshell || true
# wrapper at each call site, and internal commands are guarded individually.

set -uo pipefail

# Latest release by default; export SANDCAT_VERSION=vX.Y.Z to pin (rollback
# knob -- no code change needed).
SANDCAT_VERSION="${SANDCAT_VERSION:-latest}"
SANDCAT_BIN="${HOME}/.local/bin/sandcat"

# Published names are calico-mcp-<version>-<os>-<arch>, where <version> is either
# the moving pointer "dev-latest" or an immutable "<ver>-<commit>" (e.g.
# 0.4.0-dev-fa66118aa5e1), so CALICO_MCP_VERSION doubles as the pin/rollback
# knob. See mcp/INSTALL.md on the feature-calico-mcp branch.
CALICO_MCP_VERSION="${CALICO_MCP_VERSION:-dev-latest}"
CALICO_MCP_BUCKET="${CALICO_MCP_BUCKET:-gs://calico-mcp}"
# Version in the cached path: the download is skipped when the file is already
# there, so a fixed name would hand back whatever an earlier run left behind
# after CALICO_MCP_VERSION changes.
CALICO_MCP_LOCAL_BIN="${CALICO_MCP_LOCAL_BIN:-${HOME}/.local/bin/calico-mcp-${CALICO_MCP_VERSION}}"

# PR description + changed-file list, fetched once per job and read by every
# diagnosis. Outside the repo, so it never shows up as a dirty working copy.
SANDCAT_PR_CONTEXT_FILE="${SANDCAT_PR_CONTEXT_FILE:-${HOME}/sandcat-pr-context.json}"

_sandcat_download() {
  if [[ -x "${SANDCAT_BIN}" ]]; then
    return 0
  fi
  if [[ -z "${GITHUB_ACCESS_TOKEN:-}" ]]; then
    echo "[WARN] sandcat: GITHUB_ACCESS_TOKEN not set; cannot download binary" >&2
    return 1
  fi
  local release_path="tags/${SANDCAT_VERSION}"
  [[ "${SANDCAT_VERSION}" == "latest" ]] && release_path="latest"
  echo "[INFO] sandcat: downloading ${SANDCAT_VERSION}..." >&2
  mkdir -p "$(dirname "${SANDCAT_BIN}")"
  local asset_url
  asset_url=$(curl -fsSL \
    -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/tigera/sandcat/releases/${release_path}" \
    | jq -r '.assets[] | select(.name == "sandcat-linux-amd64") | .url') || return 1
  curl -fsSL \
    -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" \
    -H "Accept: application/octet-stream" \
    "${asset_url}" \
    -o "${SANDCAT_BIN}" && chmod +x "${SANDCAT_BIN}"
}

# Fetch calico-mcp from GCS. No extra auth: the global prologue activates
# semaphore-v2-gce@unique-caldron-775, which is the same service account the
# "calico-mcp: publish release to GCS" block uploads with (objectAdmin on the
# bucket), and `gcloud storage` is already used here for the working-copy cache.
#
# The `--version` call at the end is the smoke test that matters: it proves the
# binary starts in this environment. A published binary that will not execute
# (wrong arch, missing libc) is otherwise only discovered by the agent, deep
# inside a failing spec's diagnosis, as a spawn error.
_calico_mcp_download() {
  if [[ -x "${CALICO_MCP_LOCAL_BIN}" ]]; then
    return 0
  fi
  if ! command -v gcloud >/dev/null; then
    echo "[WARN] calico-mcp: gcloud not installed; cannot download" >&2
    return 1
  fi
  local remote="${CALICO_MCP_BUCKET}/calico-mcp-${CALICO_MCP_VERSION}-linux-amd64"
  echo "[INFO] calico-mcp: downloading ${remote}..." >&2
  mkdir -p "$(dirname "${CALICO_MCP_LOCAL_BIN}")"
  gcloud storage cp "${remote}" "${CALICO_MCP_LOCAL_BIN}" >&2 || return 1
  chmod +x "${CALICO_MCP_LOCAL_BIN}" || return 1
  # Identifies itself as "calico-mcp <version> (<commit>)", so the job log names
  # the exact build even when CALICO_MCP_VERSION is the moving dev-latest.
  local ver
  if ! ver=$("${CALICO_MCP_LOCAL_BIN}" --version 2>&1); then
    echo "[WARN] calico-mcp: downloaded binary does not run: ${ver}" >&2
    return 1
  fi
  echo "[INFO] calico-mcp: ${ver}" >&2
}

# Fetch the PR description + changed files once, print the file's path.
#
# The fetch has to happen out here rather than inside sandcat's inline path:
# that runs once per failing spec, in a test container that holds no GitHub
# credentials and has no gh CLI.
#
# A branch run has no PR, so sandcat writes nothing and this returns non-zero
# with no path -- the caller then simply does not wire it up, which keeps every
# later diagnosis from logging a missing file it was never going to have.
cmd_fetch_pr() {
  _sandcat_download || return 1
  # Cleared first so the file can only ever describe this job's PR. The no-PR
  # case writes nothing, so on an agent with a reused home a leftover file would
  # otherwise be handed to a branch run as if it were that run's PR.
  rm -f "${SANDCAT_PR_CONTEXT_FILE}"
  # ArgoCI names these CI_GIT_*, and says "none" off a PR.
  local pr="${SEMAPHORE_GIT_PR_NUMBER:-${CI_GIT_PR_NUMBER:-}}"
  # Its stdout goes to stderr so the only thing on ours is the path below.
  "${SANDCAT_BIN}" fetch-pr \
    --repo "${CI_GIT_REPO_SLUG:-tigera/calico-private}" \
    --pr-number "${pr/#none/}" \
    --out "${SANDCAT_PR_CONTEXT_FILE}" >&2 || return 1
  [[ -s "${SANDCAT_PR_CONTEXT_FILE}" ]] || return 1
  echo "${SANDCAT_PR_CONTEXT_FILE}"
}

# Resolve everything the inline per-spec failure hook needs, and print it as
# KEY=VALUE lines for the caller to eval. Exits non-zero when inline diagnosis
# must not run, having already said why on stderr.
#
# The two callers place the hook very differently -- run_tests.sh bind-mounts
# the binaries into the e2e run container, the KinD path runs ginkgo straight on
# the host -- so the paths printed here are host paths and each caller maps them
# to whatever its process will see. What is shared is the policy: which binaries
# are needed, whether calico-mcp can actually reach the cluster, and the budget
# each job diagnoses under.
#
# Deliberately placed before the upload-token gate: the hook writes files for
# the epilogue to publish and uploads nothing itself, so it needs only a Gemini
# key and GITHUB_ACCESS_TOKEN. A job holding gemini-api-key alone still gets it.
cmd_inline_env() {
  # The payload the callers eval is the only thing this may put on stdout, so
  # send stdout to stderr for the body and keep the real one on fd 3. Without
  # this, any write to stdout from here down lands in the KEY=VALUE stream and
  # is eval'd as shell: `check-mcp` prints "calico-mcp ok: N tools registered,
  # cluster answered" on a *healthy* probe, and its no-reachability variant
  # contains `(` and `;`, so the healthiest runs would abort the job outright.
  # Command substitution overrides fd 1 inside its own subshell, so the
  # `$(_sandcat_download && ...)` captures below still see what they expect.
  exec 3>&1 1>&2

  local kubeconfig="" source_dir="."
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --kubeconfig) kubeconfig="$2"; shift 2 ;;
      --source-dir) source_dir="$2"; shift 2 ;;
      *) shift ;;
    esac
  done

  # Cleared up front, not as part of the fetch below: every refusal after this
  # point returns early, and on an agent with a reused home a file left by an
  # earlier job would then survive into the epilogue's `analyze`, which reads
  # the same path -- so a job whose calico-mcp was refused would reason about,
  # and blame, the previous job's PR.
  rm -f "${SANDCAT_PR_CONTEXT_FILE}"

  # sandcat accepts either name; a job may carry sandcat-nightly, gemini-api-key
  # or both. Absence is the normal case for a job that has not been granted a
  # key, but it has to say so: with no line here, a job that never attempted
  # inline diagnosis reads exactly like one that attempted it and found nothing.
  local gemini_key="${SANDCAT_GEMINI_KEY:-${GEMINI_API_KEY:-}}"
  if [[ -z "${gemini_key}" ]]; then
    echo "[INFO] sandcat: inline per-spec diagnosis off — neither SANDCAT_GEMINI_KEY nor GEMINI_API_KEY is set" >&2
    return 1
  fi

  local bin
  bin=$(_sandcat_download 3>&- && echo "${SANDCAT_BIN}")
  if [[ ! -x "${bin}" ]]; then
    echo "[WARN] sandcat: inline diagnosis requested (a Gemini key is set) but the binary is unavailable (see above); skipping" >&2
    return 1
  fi

  # Say whether the cost metrics will be recorded. An un-enabled Semaphore
  # secret injects nothing at all -- no error, no warning -- so without this
  # line "no metrics were recorded" and "metrics are switched off" look
  # identical from the outside. The token is never printed, only whether it
  # arrived. sandcat reads both from its own environment, on either lane, so
  # this reports rather than resolves them.
  #
  # Reported here rather than next to the payload: every check below can refuse,
  # and the state of a secret is worth knowing on a job that ends up not
  # diagnosing anything -- that is when someone is reading the log.
  local db_missing=()
  [[ -n "${SANDCAT_DB_URL:-}" ]] || db_missing+=("SANDCAT_DB_URL")
  [[ -n "${SANDCAT_DB_TOKEN:-}" ]] || db_missing+=("SANDCAT_DB_TOKEN")
  if [[ ${#db_missing[@]} -eq 0 ]]; then
    echo "[INFO] sandcat: metrics enabled (${SANDCAT_DB_URL})"
  else
    echo "[INFO] sandcat: metrics off - the sandcat-db secret did not provide ${db_missing[*]}; check it is enabled in this project's secret settings"
  fi

  # calico-mcp gives the agent the Calico diagnostic catalog against the still-live
  # cluster. On by default: since the agent's kubectl tools were replaced by this
  # catalog, a run without it has no cluster access at all. SANDCAT_CALICO_MCP=0
  # opts out -- the rollback lever if a calico-mcp build misbehaves -- and accepts
  # source-tree-only diagnoses for that job. The test is a value test, not -n, so
  # that 0 is a real off switch: with a default of 1, an empty value cannot
  # express "disabled".
  local mcp_bin="" mcp_state=off
  if [[ "${SANDCAT_CALICO_MCP:-1}" != "0" ]]; then
    local mcp_why=""
    mcp_bin=$(_calico_mcp_download 3>&- && echo "${CALICO_MCP_LOCAL_BIN}")
    if [[ ! -x "${mcp_bin}" ]]; then
      mcp_why="download or its --version check failed (see the calico-mcp lines above)"
    else
      # Probe the integration once, here, rather than discovering it per failing
      # spec: `check-mcp` spawns the server, wires it to the cluster and lists the
      # catalog -- exactly what a diagnosis needs and nothing more (no Gemini key,
      # no model call, a couple of seconds).
      #
      # The natural home for this would be ginkgo's SynchronizedBeforeSuite, inside
      # the suite -- but a suite may declare only one and the upstream k8s e2e
      # framework already does. The host has the same binaries and the same
      # cluster, so it answers the same question a step earlier.
      #
      # Only exit 3 (sandcat's "calico-mcp unavailable") disables anything. Every
      # other non-zero is ambiguous -- most importantly it is what a sandcat
      # release predating `check-mcp` returns for an unknown command -- and
      # disabling diagnosis on an ambiguous signal would be worse than not probing
      # at all. A genuine failure that this misses still surfaces per spec, where
      # sandcat exits 3 and the hook stops trying.
      #
      # Bounded, and with fd 3 closed for it and its children. The probe spawns
      # a server and talks to the cluster, so it is the one thing here that can
      # both hang and outlive its parent -- and this whole function runs inside
      # the caller's `$( )`, whose pipe stays open as long as any process holds
      # the write end. An orphaned calico-mcp inheriting fd 3 would therefore
      # stall the caller indefinitely: on the KinD lane, between kind-up and the
      # suite, that is the pipeline's 4h limit with zero tests run.
      #
      # A timeout is its own answer, not an ambiguous one: 124 is this script's
      # code, not a sandcat exit status, and a probe that could not finish is
      # evidence the diagnoses would not either.
      local probe_rc=0
      timeout "${SANDCAT_MCP_PROBE_TIMEOUT:-120}" \
        "${bin}" check-mcp --calico-mcp "${mcp_bin}" --kubeconfig "${kubeconfig}" 3>&- || probe_rc=$?
      case "${probe_rc}" in
        3)   mcp_why="check-mcp could not wire it to the cluster (reason above)" ;;
        124) mcp_why="check-mcp did not finish within ${SANDCAT_MCP_PROBE_TIMEOUT:-120}s" ;;
      esac
    fi
    if [[ -n "${mcp_why}" ]]; then
      # Diagnosing without the live-cluster tools is worse than not diagnosing:
      # the agent falls back to reading the source tree, spends the model budget,
      # and returns a verdict that looks like every other verdict. So drop the
      # whole inline setup and say so at ERROR, which is what CI triage quotes.
      echo "[ERROR] sandcat: calico-mcp unavailable — ${mcp_why}; skipping inline per-spec diagnosis" >&2
      return 1
    fi
    mcp_state=on
  fi

  # The PR's description and changed-file list: the inputs that say whether this
  # change could plausibly have broken the failing spec. The hook's environment
  # carries only the PR's number and title, and neither the test container nor
  # the precompiled suite can fetch the rest -- no GitHub credentials, no gh CLI
  # -- so fetch it once here for every diagnosis to read.
  #
  # Left empty when the fetch produced nothing. A branch run has no PR, and
  # pointing the hook at a file that will never exist would have each failing
  # spec log a miss for something it was never going to get.
  local pr_ctx
  pr_ctx=$(cmd_fetch_pr 3>&-) || pr_ctx=""

  # What each caller does with these is its own business, but one rule is not:
  # every path the hook is given has to be absolute. Its defaults are relative,
  # and ginkgo runs a precompiled suite with its working directory set to the
  # directory holding the binary ("Running Suite: ... - .../e2e/bin/k8s"), not
  # the directory ginkgo itself was invoked from -- so a relative out dir lands
  # in e2e/bin/k8s/report/sandcat, which nothing collects, while --output-dir is
  # resolved by the ginkgo CLI and puts the reports at the repo root. The
  # diagnoses have to end up next to report.json, which is where the epilogue's
  # `analyze` looks for them.
  printf '%s=%q\n' >&3 \
    SANDCAT_INLINE_BIN "${bin}" \
    SANDCAT_INLINE_CALICO_MCP_BIN "${mcp_bin}" \
    SANDCAT_INLINE_PR_CONTEXT "${pr_ctx}" \
    SANDCAT_INLINE_GEMINI_KEY "${gemini_key}" \
    SANDCAT_INLINE_SHA "$(git -C "${source_dir}" rev-parse HEAD 2>/dev/null || echo "")" \
    SANDCAT_SIG_DIR /tmp/sandcat-sigs \
    SANDCAT_MAX_DIAGNOSES "${SANDCAT_MAX_DIAGNOSES:-10}" \
    SANDCAT_TOTAL_BUDGET "${SANDCAT_TOTAL_BUDGET:-25m}"

  # Emitted last, so it reflects what was actually set up rather than what was
  # intended a few lines earlier.
  echo "[INFO] sandcat: inline per-spec diagnosis enabled (calico-mcp: ${mcp_state})" >&2
}

_sandcat_common_vars() {
  SANDCAT_SHA=$(git -C "${SOURCE_DIR:-.}" rev-parse HEAD 2>/dev/null || echo "")
  SANDCAT_JOB_URL="https://tigera.semaphoreci.com/jobs/${SEMAPHORE_JOB_ID:-}"
}

# Print the newest of the given paths, ignoring any that do not exist, so an
# unmatched glob is an empty result rather than an error. Returns non-zero when
# none of them exist.
_sandcat_newest() {
  local newest="" f
  for f in "$@"; do
    [[ -f "${f}" ]] || continue
    if [[ -z "${newest}" || "${f}" -nt "${newest}" ]]; then newest="${f}"; fi
  done
  [[ -n "${newest}" ]] || return 1
  printf '%s\n' "${newest}"
}

# The expansion to remove when this script ends. A global because the handler
# reads it when the signal arrives, by which time the local that named it is
# long out of scope -- which is also why the trap body can stay single-quoted
# and needs no quoting of the path into it.
_SANDCAT_TMP_LOG=""

# Delete path when this script ends, however it ends.
#
# Cleanup hangs off EXIT alone, so there is one place that removes the file. The
# signal traps only ask the shell to leave, which is what it would have done
# with no trap at all: a handler that just cleans up and returns leaves bash to
# resume the script, so a job-timeout SIGTERM landing during the download would
# delete the expansion and then run the analysis against the path it just
# removed. Exiting from the handler runs the EXIT trap on the way out.
_sandcat_rm_on_exit() {
  _SANDCAT_TMP_LOG="$1"
  trap 'rm -f "${_SANDCAT_TMP_LOG}"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

# Push the newest local run record (written by `sandcat analyze` under
# data/runs/) to the Semaphore job artifacts.
_sandcat_push_artifact() {
  command -v artifact >/dev/null || return 0
  local newest
  newest=$(_sandcat_newest data/runs/*.json) || return 0
  echo "[INFO] sandcat: pushing analysis to job artifacts"
  artifact push job "${newest}" --destination semaphore/sandcat-analysis.json || true
}

# Emit one JSON object per inline-diagnosed spec, read from the per-spec
# directories the ginkgo failure hook and `sandcat diagnose-spec` write. Each
# object already names its spec, so the caller only has to slurp them into an
# array.
#
# A spec whose diagnosis died before writing analysis.json is still emitted,
# synthesised from the result.json the hook wrote before invoking sandcat —
# otherwise a crashed diagnosis would leave no trace of the failure at all.
# Every read is best-effort: one unreadable directory must not empty the index.
_sandcat_specs_index() {
  local dir="$1" d slug
  for d in "${dir}"/*/; do
    [[ -d "${d}" ]] || continue
    slug="$(basename "${d%/}")"
    if [[ -s "${d}analysis.json" ]]; then
      # Passed through jq rather than cat so a truncated file is dropped on its
      # own instead of failing the slurp and losing every other spec with it.
      jq -c '.' "${d}analysis.json" || true
    elif [[ -s "${d}result.json" ]]; then
      jq --arg slug "${slug}" \
        '{spec: (.specs[0].name // .test_name // ""),
          slug: $slug,
          verdict: "no-analysis",
          state: (.specs[0].state // ""),
          failure: ((.specs[0].failure // "")[0:2000])}' \
        "${d}result.json" || true
    fi
  done
}

# Push the inline per-spec diagnoses as a single flat array. The directories
# themselves stay local: a consumer cannot discover them, because `artifact
# list` reports the enclosing directory and needs a path per level to descend.
# One known path costs a single fetch and keeps every spec name in the payload.
cmd_push_specs() {
  local spec_dir="" report=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --spec-dir) spec_dir="$2"; shift 2 ;;
      --report)   report="$2"; shift 2 ;;
      *) shift ;;
    esac
  done

  # The hook writes beside the ginkgo report, so the report names the directory
  # whenever the caller does not.
  if [[ -z "${spec_dir}" && -n "${report}" ]]; then
    spec_dir="$(dirname "${report}")/sandcat"
  fi
  [[ -n "${spec_dir}" && -d "${spec_dir}" ]] || return 0
  command -v artifact >/dev/null || return 0

  local out="${HOME}/sandcat-specs.json"
  # jq stderr is left visible: this directory only exists because a spec failed,
  # so an empty or unwritable index means something went wrong and the job log
  # is the only place to find out what.
  if _sandcat_specs_index "${spec_dir}" | jq -s '.' >"${out}" &&
    jq -e 'length > 0' "${out}" >/dev/null; then
    echo "[INFO] sandcat: pushing inline per-spec diagnoses"
    artifact push job "${out}" --destination semaphore/sandcat-specs.json || true
  else
    echo "[WARN] sandcat: no inline diagnoses collected from ${spec_dir}" >&2
  fi
}

cmd_analyze() {
  local report=""
  local log_file=""
  local kubeconfig=""
  local source_dir="."
  local spec_dir=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --report)      report="$2"; shift 2 ;;
      --log-file)    log_file="$2"; shift 2 ;;
      --kubeconfig)  kubeconfig="$2"; shift 2 ;;
      --source-dir)  source_dir="$2"; shift 2 ;;
      --spec-dir)    spec_dir="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  SOURCE_DIR="${source_dir}"

  if [[ -z "${report}" || ! -f "${report}" ]]; then
    echo "[INFO] sandcat: no report file; skipping analysis"
    return 0
  fi

  _sandcat_download || { echo "[WARN] sandcat: download failed"; return 0; }
  _sandcat_common_vars

  # The per-run analysis runs on the host, where the cluster is still up, so it
  # can use the live-cluster tools too. Handed over as CALICO_MCP_BIN rather than
  # a --calico-mcp flag: an older sandcat release ignores an env var it doesn't
  # know, but dies on an unrecognised flag, and SANDCAT_VERSION can pin any
  # release independently of this script.
  #
  # On by default; SANDCAT_CALICO_MCP=0 opts out and accepts a source-tree-only
  # analysis. Failing to fetch it skips the analysis rather than running a weaker
  # one, for the same reason the inline path does: an unmarked weak verdict is
  # uploaded, surfaced in the UI and DM'd like any other, so it costs more than
  # the missing record does.
  if [[ "${SANDCAT_CALICO_MCP:-1}" != "0" ]]; then
    if ! _calico_mcp_download; then
      echo "[ERROR] sandcat: calico-mcp unavailable; skipping analysis (set SANDCAT_CALICO_MCP=0 to analyze without live-cluster tools)"
      return 0
    fi
    export CALICO_MCP_BIN="${CALICO_MCP_LOCAL_BIN}"
  fi

  # Where the ginkgo failure hook wrote its per-spec diagnoses. sandcat derives
  # this from the report path by default, which is right for run_tests.sh
  # (--report report/report.json from the repo root, so report/sandcat is its
  # sibling) but wrong for the epilogue fallback, whose report lives in a
  # different tree. Handed over as an env var rather than a flag for the same
  # reason as CALICO_MCP_BIN: an older sandcat release ignores an env var it does
  # not know, but dies on an unrecognised flag.
  [[ -n "${spec_dir}" ]] && export SANDCAT_SPEC_DIR="${spec_dir}"

  # The same gzip trap the build-failure path closes: --log-file is a plain read
  # in the binary, so a compressed one is read as text and silently contributes
  # nothing. Today run_tests.sh's e2e branch hands over a plain log while its
  # sibling branch and every setup phase gzip theirs, so this costs nothing --
  # and the day the last plain writer is harmonised with the rest, nothing here
  # has to notice. Expanding to nothing drops the flag rather than the analysis:
  # the report, not the log, is what this path is built on.
  if [[ -n "${log_file}" && -f "${log_file}" ]]; then
    local plain_log
    plain_log=$(_sandcat_plain_log "${log_file}") || plain_log=""
    if [[ -n "${plain_log}" && "${plain_log}" != "${log_file}" ]]; then
      # Expanded now, not at trap time: plain_log is local to this function and
      # the trap fires after it has returned.
      _sandcat_rm_on_exit "${plain_log}"
    fi
    log_file="${plain_log}"
  fi

  local extra_args=()
  [[ -n "${log_file}" ]]   && extra_args+=(--log-file "${log_file}")
  [[ -n "${kubeconfig}" ]] && extra_args+=(--kubeconfig "${kubeconfig}")
  # Reuse the file the inline setup already fetched, so the per-run analysis and
  # the inline diagnoses reason about the same PR and the job spends one API
  # call on it. Absent -- a job with no inline layer, or one where inline-env
  # refused and cleared it -- the binary fetches it itself; this runs on the
  # agent, which has the credentials.
  [[ -s "${SANDCAT_PR_CONTEXT_FILE}" ]] && extra_args+=(--pr-context "${SANDCAT_PR_CONTEXT_FILE}")

  echo "[INFO] sandcat: analyzing (sha=${SANDCAT_SHA:-unknown})..."
  "${SANDCAT_BIN}" analyze \
    --ginkgo-report "${report}" \
    --sha "${SANDCAT_SHA}" \
    --repo tigera/calico-private \
    --source-dir "${source_dir}" \
    --ci-job-url "${SANDCAT_JOB_URL}" \
    --ci-job-name "${SEMAPHORE_JOB_NAME:-}" \
    --agent \
    --upload "${SANDCAT_UPLOAD_URL}" \
    --timeout 10m \
    ${extra_args[@]+"${extra_args[@]}"} \
    || echo "[WARN] sandcat: analysis failed (non-fatal)"

  _sandcat_push_artifact
  touch "${HOME}/.sandcat-analyzed"
}

# Ceiling on what an expansion may write to the agent's disk. Only the copy this
# script creates is bounded -- a plain log is handed over untouched, because it
# costs nothing and is the caller's file. A gzip is bounded because the ratio is
# the caller's, not ours: ${TEST_TYPE}-tests.log.gz on the bz lane holds a whole
# test run and expands to something the end-of-job disk may not have room for.
SANDCAT_MAX_LOG_BYTES="${SANDCAT_MAX_LOG_BYTES:-16777216}"

# Pick the log most likely to explain a job that died before its tests ran:
# the newest one the phases wrote, whether or not it is compressed.
#
# Every setup phase on the standard lane writes a *gzipped* log --
# initialize.log.gz, provision.log.gz, install.log.gz, operator_migrate.log.gz,
# upgrade.log.gz, <TYPE>-build.log.gz -- while the HCP lane and the local e2e
# runner write plain ones.
#
# diagnostic.log and destroy.log are excluded: the epilogue writes them itself,
# after the failure, and they describe teardown rather than what went wrong.
# That list is load-bearing against a newest-wins pick and its write sites are
# in global_epilogue.sh, which carries a matching note -- a new log teed there
# would be, by construction, the newest file in the directory.
# Emits every candidate, newest first, rather than committing to one. The caller
# walks them until a log yields content, because the newest name is not always a
# readable log: `tee >(gzip --stdout > install.log.gz)` creates the file the
# instant the phase starts, but gzip buffers ~32 KiB before it flushes anything,
# so a phase killed under that leaves a zero-byte install.log.gz -- the newest
# file in the directory, and empty. Stopping there would discard the populated
# log of the phase before it on exactly the killed-mid-setup failure this path
# exists for.
#
# Ordered by repeated newest-selection rather than by a timestamp sort, so the
# comparison stays the shell's own `-nt` and does not depend on the resolution
# `stat` happens to report. There are a handful of files.
_sandcat_pick_build_logs() {
  local dir="$1" remaining=() f newest rest
  for f in "${dir}"/*.log "${dir}"/*.log.gz; do
    [[ -f "${f}" ]] || continue
    # Compare against the uncompressed name so each exclusion is spelled once.
    case "${f%.gz}" in
      */diagnostic.log|*/destroy.log) continue ;;
    esac
    remaining+=("${f}")
  done
  while [[ ${#remaining[@]} -gt 0 ]]; do
    newest=$(_sandcat_newest "${remaining[@]}") || break
    printf '%s\n' "${newest}"
    rest=()
    for f in "${remaining[@]}"; do
      [[ "${f}" == "${newest}" ]] || rest+=("${f}")
    done
    remaining=("${rest[@]}")
  done
}

# A log past the ceiling keeps both ends and drops the middle.
#
# The head alone is the wrong half. A failure is the last thing a phase writes,
# and sandcat's own reader wants the end too: it anchors on the tail of the log
# and takes the last lines before the diagnostics banner. Handing it the opening
# 16 MiB of a long run gives it lines from the middle to read as the failure --
# worse than handing it nothing, because it looks like evidence.
#
# The head is kept as well, in a quarter of the budget, because it names the
# phase and the configuration it ran with, and the tail alone starts mid-sentence.
#
# The head is already on disk from the bounded first pass, so the log is read a
# second time only in this case, which is the rare one.
_sandcat_keep_both_ends() {
  local log_file="$1" plain="$2"
  local head_bytes=$(( SANDCAT_MAX_LOG_BYTES / 4 ))
  local tail_bytes=$(( SANDCAT_MAX_LOG_BYTES - head_bytes ))
  truncate -s "${head_bytes}" "${plain}" || return 1
  printf '\n[sandcat] the middle of this log was skipped: it expands past %s bytes, so only its first %s and last %s are here\n\n' \
    "${SANDCAT_MAX_LOG_BYTES}" "${head_bytes}" "${tail_bytes}" >> "${plain}"
  local tail_rc=0
  gzip -dc "${log_file}" 2>/dev/null | tail -c "${tail_bytes}" >> "${plain}"
  tail_rc="${PIPESTATUS[0]}"
  # Over the ceiling *and* unreadable to the end: the tail is the tail of what
  # could be recovered, not of the log, and the reader has to be told.
  if (( tail_rc != 0 )); then
    printf '\n[sandcat] this log is incomplete -- the compressed stream could not be read to the end, so anything after this point is missing\n' >> "${plain}"
  fi
  echo "[WARN] sandcat: ${log_file##*/} expands past ${SANDCAT_MAX_LOG_BYTES} bytes; analyzing its first ${head_bytes} and last ${tail_bytes}" >&2
}

# sandcat reads --log-file as plain text, so a gzipped one has to be expanded
# first. Prints the path to use, which is the original when it is not gzipped,
# and nothing at all when there is no readable content behind it.
#
# Detected by magic number rather than by name: the caller may have been handed
# any path, and this is the one check that cannot be wrong about it.
#
# `gzip -dc` failing is not fatal. `tee >(gzip --stdout > ...)` leaves a
# truncated stream behind when a job is killed mid-phase, and the prefix it can
# still recover is usually the whole story -- so keep what came out and mark the
# cut, rather than discarding it and falling back to a record that says nothing.
# Recovering nothing is the one case that is not salvage: a file holding only
# the marker is a sentence this script wrote about a log it never read, and it
# would be analyzed as if it were evidence.
_sandcat_plain_log() {
  local log_file="$1"
  # An empty or unreadable log is nothing to analyze whichever kind it is, and
  # saying so here keeps the two kinds from disagreeing about it: the sniff
  # below cannot read such a file either, and would call it plain.
  [[ -r "${log_file}" && -s "${log_file}" ]] || return 1
  if [[ "$(head -c 2 "${log_file}" 2>/dev/null | od -An -tx1 | tr -d ' \n')" != "1f8b" ]]; then
    echo "${log_file}"
    return 0
  fi
  local plain
  plain=$(mktemp "${TMPDIR:-/tmp}/sandcat-build-log.XXXXXX") || return 1
  # `head -c` bounds the write, so the cap is on what lands on disk rather than
  # on what is thrown away afterwards. It also closes the pipe, which kills gzip
  # with SIGPIPE -- so the size decides which of the two conditions this is, and
  # gzip's status is only consulted when the cap was not reached. One byte over
  # the ceiling is asked for so that a log which happens to be exactly the cap
  # is not reported as cut.
  local gzip_rc=0
  gzip -dc "${log_file}" 2>/dev/null | head -c "$(( SANDCAT_MAX_LOG_BYTES + 1 ))" > "${plain}"
  gzip_rc="${PIPESTATUS[0]}"
  local size
  size=$(stat -c %s "${plain}" 2>/dev/null || echo 0)
  if (( size == 0 )); then
    rm -f "${plain}"
    return 1
  fi
  if (( size > SANDCAT_MAX_LOG_BYTES )); then
    _sandcat_keep_both_ends "${log_file}" "${plain}"
  elif (( gzip_rc != 0 )); then
    echo "[WARN] sandcat: ${log_file##*/} could not be read to the end; analyzing what came out" >&2
    printf '\n[sandcat] this log is incomplete -- the compressed stream could not be read to the end, so anything after this point is missing\n' >> "${plain}"
  fi
  echo "${plain}"
}

cmd_build_failure() {
  local source_dir="."
  local log_file=""
  local logs_dir=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --source-dir) source_dir="$2"; shift 2 ;;
      --log-file)   log_file="$2"; shift 2 ;;
      --logs-dir)   logs_dir="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  SOURCE_DIR="${source_dir}"
  _sandcat_common_vars

  # A caller that knows which log it wants names it; one that only knows where
  # the phases write theirs hands over the directory and takes the newest that
  # can actually be read.
  local plain_log=""
  if [[ -n "${log_file}" ]]; then
    [[ -f "${log_file}" ]] && { plain_log=$(_sandcat_plain_log "${log_file}") || plain_log=""; }
  elif [[ -n "${logs_dir}" ]]; then
    local cand
    while IFS= read -r cand; do
      if plain_log=$(_sandcat_plain_log "${cand}"); then
        log_file="${cand}"
        echo "[INFO] sandcat: build failure log is ${log_file##*/}"
        break
      fi
      plain_log=""
      echo "[INFO] sandcat: ${cand##*/} holds nothing readable; trying the phase before it"
    done < <(_sandcat_pick_build_logs "${logs_dir}")
  fi

  # Armed the moment the copy exists, so every way out of here frees it --
  # including the ten minutes the analysis below may spend before a job kill.
  # Only the expanded copy: when the log needed no expanding the two paths are
  # the same file and it is the caller's, not ours.
  if [[ -n "${plain_log}" && "${plain_log}" != "${log_file}" ]]; then
    # Expanded now, not at trap time: plain_log is local to this function and
    # the trap fires after it has returned.
    _sandcat_rm_on_exit "${plain_log}"
  fi

  # Log-only agent analysis extracts the real error; synthetic record is the fallback.
  if [[ -n "${plain_log}" ]] && _sandcat_download; then
    echo "[INFO] sandcat: analyzing build failure from log (sha=${SANDCAT_SHA:-unknown})..."
    if "${SANDCAT_BIN}" analyze \
      --log-file "${plain_log}" \
      --sha "${SANDCAT_SHA}" \
      --repo tigera/calico-private \
      --source-dir "${source_dir}" \
      --ci-job-url "${SANDCAT_JOB_URL}" \
      --ci-job-name "${SEMAPHORE_JOB_NAME:-}" \
      --agent \
      --upload "${SANDCAT_UPLOAD_URL}" \
      --timeout 10m; then
      _sandcat_push_artifact
      return 0
    fi
    echo "[WARN] sandcat: log analysis failed; falling back to synthetic record"
  fi

  echo "[INFO] sandcat: uploading build-failure record"
  # CI merge commits resolve to the second parent, matching the binary's behavior.
  local commit_ref="${SANDCAT_SHA}" commit_msg="" commit_author=""
  if [[ -n "${SANDCAT_SHA}" ]]; then
    local subject parents
    subject=$(git -C "${source_dir}" log -1 --format=%s "${SANDCAT_SHA}" 2>/dev/null || echo "")
    parents=$(git -C "${source_dir}" log -1 --format=%P "${SANDCAT_SHA}" 2>/dev/null || echo "")
    if [[ "${subject}" == Merge\ * && $(wc -w <<< "${parents}") -eq 2 ]]; then
      commit_ref=$(awk '{print $2}' <<< "${parents}")
    fi
    commit_msg=$(git -C "${source_dir}" log -1 --format=%s "${commit_ref}" 2>/dev/null || echo "")
    commit_author=$(git -C "${source_dir}" log -1 --format=%an "${commit_ref}" 2>/dev/null || echo "")
  fi
  local run_id now payload
  run_id="$(date -u +%Y%m%d-%H%M%S)-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  payload=$(jq -n \
    --arg id "$run_id" \
    --arg started "$now" \
    --arg finished "$now" \
    --arg sha "$SANDCAT_SHA" \
    --arg commit_msg "$commit_msg" \
    --arg commit_author "$commit_author" \
    --arg test_name "${SEMAPHORE_JOB_NAME:-build}" \
    --arg ci_job_url "$SANDCAT_JOB_URL" \
    --arg ci_job_name "${SEMAPHORE_JOB_NAME:-}" \
    '{run: {id: $id, started_at: $started, finished_at: $finished,
            repo: "tigera/calico-private", sha: $sha, test_name: $test_name,
            commit_msg: $commit_msg, commit_author: $commit_author,
            passed: false, verdict: "infra", confidence: 1.0,
            root_cause: "Build/setup failed before tests could run. No JUnit report was produced.",
            broken_by: "", ci_job_url: $ci_job_url, ci_job_name: $ci_job_name},
     report: null}')

  curl -fsSL -X POST "${SANDCAT_UPLOAD_URL}" \
    -H "Authorization: Bearer ${SANDCAT_INGEST_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${payload}" || echo "[WARN] sandcat: build-failure upload failed (non-fatal)"

  if command -v artifact >/dev/null; then
    printf '%s\n' "${payload}" > sandcat-build-failure.json
    artifact push job sandcat-build-failure.json --destination semaphore/sandcat-analysis.json || true
  fi
}

# --- entry point ---
subcmd="${1:-}"
shift || true

# `download` fetches the binary (idempotent) and prints its path. It needs only
# GITHUB_ACCESS_TOKEN, not the upload/ingest tokens, so it runs before the
# upload gate below. Kept for running sandcat by hand on an agent: the inline
# setup calls the same helper directly, through inline-env.
if [[ "${subcmd}" == "download" ]]; then
  _sandcat_download || exit 1
  echo "${SANDCAT_BIN}"
  exit 0
fi

if [[ "${subcmd}" == "fetch-pr" ]]; then
  cmd_fetch_pr || exit 1
  exit 0
fi

# Resolve the whole inline per-spec setup and print it for the caller to eval.
# Same gating as `download`: the hook writes files for the epilogue to publish
# and uploads nothing itself, so it needs no upload secrets and works on a job
# carrying only a Gemini key.
if [[ "${subcmd}" == "inline-env" ]]; then
  cmd_inline_env "$@" || exit 1
  exit 0
fi

# Same contract as `download`, for calico-mcp: fetch it and print its path, with
# no upload/ingest tokens needed. Also kept for use by hand -- inline-env
# resolves calico-mcp itself.
if [[ "${subcmd}" == "download-calico-mcp" ]]; then
  _calico_mcp_download || exit 1
  echo "${CALICO_MCP_LOCAL_BIN}"
  exit 0
fi

# Moves files the hook already wrote, so it runs without the ingest/upload
# tokens the analysis paths below require.
if [[ "${subcmd}" == "push-specs" ]]; then
  cmd_push_specs "$@"
  exit 0
fi

if [[ -z "${SANDCAT_INGEST_TOKEN:-}" || -z "${SANDCAT_UPLOAD_URL:-}" ]]; then
  # Name what is missing. Exiting silently made "sandcat analysed the job and
  # found nothing" and "sandcat never ran" look identical from the job log,
  # which is a whole debugging session on its own.
  #
  # A job that reaches here on a fork PR is usually missing the secret from the
  # project's fork-PR allowlist rather than from its own block: the block's
  # `secrets:` list is necessary but not sufficient there.
  _sandcat_missing=""
  if [[ -z "${SANDCAT_INGEST_TOKEN:-}" ]]; then _sandcat_missing="SANDCAT_INGEST_TOKEN"; fi
  if [[ -z "${SANDCAT_UPLOAD_URL:-}" ]]; then _sandcat_missing="${_sandcat_missing:+${_sandcat_missing} }SANDCAT_UPLOAD_URL"; fi
  echo "[INFO] sandcat: skipping '${subcmd}' — unset: ${_sandcat_missing}" >&2
  exit 0
fi

case "${subcmd}" in
  analyze)       cmd_analyze "$@" ;;
  build-failure) cmd_build_failure "$@" ;;
  *)             echo "[ERROR] sandcat.sh: unknown subcommand '${subcmd}'" >&2; exit 1 ;;
esac
