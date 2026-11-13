#!/usr/bin/env bash
# Shared helper that downloads and runs the sandcat CI failure analyzer. Every
# failure is non-fatal; call sites wrap it in `|| true`.
#
# Usage:
#   sandcat.sh analyze             analyze a ginkgo report and upload the result
#     --spec-dir DIR               inline diagnoses dir, when not beside the report
#   sandcat.sh build-failure       analyze the job log, or record the failure without one
#     --log-file FILE | --logs-dir DIR
#   sandcat.sh cut-off             record a job whose analysis was stopped at its limit
#     --after DURATION
#   sandcat.sh push-specs          push the inline diagnoses as one artifact
#     --spec-dir DIR | --report FILE
#   sandcat.sh download            fetch the binary, print its path
#   sandcat.sh fetch-pr            fetch the PR context file, print its path
#   sandcat.sh download-calico-mcp fetch calico-mcp, print its path
#   sandcat.sh inline-env          print the inline hook setup as KEY=VALUE lines;
#     --kubeconfig PATH --source-dir DIR   non-zero means do not run the hook
#
# Env: SANDCAT_INGEST_TOKEN and SANDCAT_UPLOAD_URL gate analyze and build-failure
# (skipped when unset). GITHUB_ACCESS_TOKEN downloads the binary.
# SANDCAT_CALICO_MCP=0 disables calico-mcp; CALICO_MCP_VERSION pins it.

set -uo pipefail

# Set SANDCAT_VERSION=vX.Y.Z to pin a release.
SANDCAT_VERSION="${SANDCAT_VERSION:-latest}"
SANDCAT_BIN="${HOME}/.local/bin/sandcat"

# Either the moving "dev-latest" or an immutable "<ver>-<commit>" build.
CALICO_MCP_VERSION="${CALICO_MCP_VERSION:-dev-latest}"
CALICO_MCP_BUCKET="${CALICO_MCP_BUCKET:-gs://calico-mcp}"
# Versioned path: the cached download would otherwise survive a version change.
CALICO_MCP_LOCAL_BIN="${CALICO_MCP_LOCAL_BIN:-${HOME}/.local/bin/calico-mcp-${CALICO_MCP_VERSION}}"

# Outside the repo so it never dirties the working copy.
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
  asset_url=$(_github_curl \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/tigera/sandcat/releases/${release_path}" \
    | jq -r '.assets[] | select(.name == "sandcat-linux-amd64") | .url') || return 1
  _github_curl \
    -H "Accept: application/octet-stream" \
    "${asset_url}" \
    -o "${SANDCAT_BIN}" && chmod +x "${SANDCAT_BIN}"
}

# The token reaches curl on stdin, so it never shows in the process list.
_github_curl() {
  curl -fsSL -K - "$@" <<<"header = \"Authorization: token ${GITHUB_ACCESS_TOKEN}\""
}

# The --version call proves the binary runs here (wrong arch, missing libc).
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
  local ver
  if ! ver=$("${CALICO_MCP_LOCAL_BIN}" --version 2>&1); then
    echo "[WARN] calico-mcp: downloaded binary does not run: ${ver}" >&2
    return 1
  fi
  echo "[INFO] calico-mcp: ${ver}" >&2
}

# Print the PR context file's path; non-zero on a branch run, which has no PR.
# Fetched out here because the test container has no GitHub credentials.
cmd_fetch_pr() {
  _sandcat_download || return 1
# Cleared first so a reused home cannot hand a branch run an older PR.
  rm -f "${SANDCAT_PR_CONTEXT_FILE}"
  # Its stdout goes to stderr so the only thing on ours is the path below.
  "${SANDCAT_BIN}" fetch-pr \
    --out "${SANDCAT_PR_CONTEXT_FILE}" >&2 || return 1
  [[ -s "${SANDCAT_PR_CONTEXT_FILE}" ]] || return 1
  echo "${SANDCAT_PR_CONTEXT_FILE}"
}

# Print the inline per-spec hook's setup as KEY=VALUE lines to eval; non-zero,
# with the reason on stderr, when the hook must not run.
cmd_inline_env() {
# Callers eval stdout, so only the payload may reach it: send everything else to
# stderr and keep the real stdout on fd 3.
  exec 3>&1 1>&2

  local kubeconfig="" source_dir="."
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --kubeconfig) kubeconfig="$2"; shift 2 ;;
      --source-dir) source_dir="$2"; shift 2 ;;
      *) shift ;;
    esac
  done

# Cleared before any early return so analyze cannot read an earlier job's PR.
  rm -f "${SANDCAT_PR_CONTEXT_FILE}"

# Say why it is off, or a job that never tried reads like one that found nothing.
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

# A secret that is not granted injects nothing and no error, so report it here.
  local db_missing=()
  [[ -n "${SANDCAT_DB_URL:-}" ]] || db_missing+=("SANDCAT_DB_URL")
  [[ -n "${SANDCAT_DB_TOKEN:-}" ]] || db_missing+=("SANDCAT_DB_TOKEN")
  if [[ ${#db_missing[@]} -eq 0 ]]; then
    echo "[INFO] sandcat: metrics enabled"
  else
    echo "[INFO] sandcat: metrics off - the sandcat-db secret did not provide ${db_missing[*]}; check it is enabled in this project's secret settings"
  fi

# Without calico-mcp the agent has no cluster access; SANDCAT_CALICO_MCP=0 opts out.
  local mcp_bin="" mcp_state=off
  if [[ "${SANDCAT_CALICO_MCP:-1}" != "0" ]]; then
    local mcp_why=""
    mcp_bin=$(_calico_mcp_download 3>&- && echo "${CALICO_MCP_LOCAL_BIN}")
    if [[ ! -x "${mcp_bin}" ]]; then
      mcp_why="download or its --version check failed (see the calico-mcp lines above)"
    else
      # Only exit 3 means calico-mcp is unavailable; other codes may come from an
      # old sandcat without check-mcp. fd 3 is closed so an orphaned server cannot
      # hold the caller's $( ) open, and the timeout bounds a hang.
      local probe_rc=0
      timeout "${SANDCAT_MCP_PROBE_TIMEOUT:-120}" \
        "${bin}" check-mcp --calico-mcp "${mcp_bin}" --kubeconfig "${kubeconfig}" 3>&- || probe_rc=$?
      case "${probe_rc}" in
        3)   mcp_why="check-mcp could not wire it to the cluster (reason above)" ;;
        124) mcp_why="check-mcp did not finish within ${SANDCAT_MCP_PROBE_TIMEOUT:-120}s" ;;
      esac
    fi
    if [[ -n "${mcp_why}" ]]; then
      # A diagnosis without live-cluster tools spends the budget on a weak verdict.
      echo "[ERROR] sandcat: calico-mcp unavailable — ${mcp_why}; skipping inline per-spec diagnosis" >&2
      return 1
    fi
    mcp_state=on
  fi

  # Empty on a branch run, which has no PR.
  local pr_ctx
  pr_ctx=$(cmd_fetch_pr 3>&-) || pr_ctx=""

  # Every path must be absolute: ginkgo runs the suite from e2e/bin/k8s, where
  # relative output is never collected.
  printf '%s=%q\n' >&3 \
    SANDCAT_INLINE_BIN "${bin}" \
    SANDCAT_INLINE_CALICO_MCP_BIN "${mcp_bin}" \
    SANDCAT_INLINE_PR_CONTEXT "${pr_ctx}" \
    SANDCAT_INLINE_GEMINI_KEY "${gemini_key}" \
    SANDCAT_INLINE_SHA "$(git -C "${source_dir}" rev-parse HEAD 2>/dev/null || echo "")" \
    SANDCAT_SIG_DIR /tmp/sandcat-sigs \
    SANDCAT_MAX_DIAGNOSES "${SANDCAT_MAX_DIAGNOSES:-10}" \
    SANDCAT_TOTAL_BUDGET "${SANDCAT_TOTAL_BUDGET:-25m}"

  echo "[INFO] sandcat: inline per-spec diagnosis enabled (calico-mcp: ${mcp_state})" >&2
}

_sandcat_common_vars() {
  SANDCAT_SHA=$(git -C "${SOURCE_DIR:-.}" rev-parse HEAD 2>/dev/null || echo "")
}

# Print the newest existing path; non-zero when none exist.
_sandcat_newest() {
  local newest="" f
  for f in "$@"; do
    [[ -f "${f}" ]] || continue
    if [[ -z "${newest}" || "${f}" -nt "${newest}" ]]; then newest="${f}"; fi
  done
  [[ -n "${newest}" ]] || return 1
  printf '%s\n' "${newest}"
}

# Global because the trap reads it after the setting function has returned.
_SANDCAT_TMP_LOG=""

# Signal traps exit rather than clean up, so the script never resumes with the
# file gone; the EXIT trap does the removal.
_sandcat_rm_on_exit() {
  _SANDCAT_TMP_LOG="$1"
  trap 'rm -f "${_SANDCAT_TMP_LOG}"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

# Push the newest data/runs/ record to the job artifacts.
_sandcat_push_artifact() {
  command -v artifact >/dev/null || return 0
  local newest
  newest=$(_sandcat_newest data/runs/*.json) || return 0
  echo "[INFO] sandcat: pushing analysis to job artifacts"
  artifact push job "${newest}" --destination sandcat/sandcat-analysis.json || true
}

# One JSON object per inline-diagnosed spec. A crashed diagnosis is synthesised
# from result.json so the failure still shows up.
_sandcat_specs_index() {
  local dir="$1" d slug
  for d in "${dir}"/*/; do
    [[ -d "${d}" ]] || continue
    slug="$(basename "${d%/}")"
    if [[ -s "${d}analysis.json" ]]; then
      # jq, not cat, so one truncated file is dropped on its own.
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

# One flat file, because `artifact list` cannot discover the per-spec directories.
cmd_push_specs() {
  local spec_dir="" report=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --spec-dir) spec_dir="$2"; shift 2 ;;
      --report)   report="$2"; shift 2 ;;
      *) shift ;;
    esac
  done

  # The hook writes beside the ginkgo report.
  if [[ -z "${spec_dir}" && -n "${report}" ]]; then
    spec_dir="$(dirname "${report}")/sandcat"
  fi
  [[ -n "${spec_dir}" && -d "${spec_dir}" ]] || return 0
  command -v artifact >/dev/null || return 0

  local out="${HOME}/sandcat-specs.json"
  # jq stderr stays visible: an empty index here means something went wrong.
  if _sandcat_specs_index "${spec_dir}" | jq -s '.' >"${out}" &&
    jq -e 'length > 0' "${out}" >/dev/null; then
    echo "[INFO] sandcat: pushing inline per-spec diagnoses"
    artifact push job "${out}" --destination sandcat/sandcat-specs.json || true
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

  # Passed as an env var, not a flag: an older sandcat dies on an unknown flag.
  # Without calico-mcp the analysis is skipped rather than run weaker.
  if [[ "${SANDCAT_CALICO_MCP:-1}" != "0" ]]; then
    if ! _calico_mcp_download; then
      echo "[ERROR] sandcat: calico-mcp unavailable; skipping analysis (set SANDCAT_CALICO_MCP=0 to analyze without live-cluster tools)"
      return 0
    fi
    export CALICO_MCP_BIN="${CALICO_MCP_LOCAL_BIN}"
  fi

  # Overrides sandcat's default of <report dir>/sandcat; env var for the same reason.
  [[ -n "${spec_dir}" ]] && export SANDCAT_SPEC_DIR="${spec_dir}"

  # sandcat reads --log-file as plain text, so a gzipped log is expanded first.
  if [[ -n "${log_file}" && -f "${log_file}" ]]; then
    local plain_log
    plain_log=$(_sandcat_plain_log "${log_file}") || plain_log=""
    if [[ -n "${plain_log}" && "${plain_log}" != "${log_file}" ]]; then
      _sandcat_rm_on_exit "${plain_log}"
    fi
    log_file="${plain_log}"
  fi

  local extra_args=()
  [[ -n "${log_file}" ]]   && extra_args+=(--log-file "${log_file}")
  [[ -n "${kubeconfig}" ]] && extra_args+=(--kubeconfig "${kubeconfig}")
  # Reuse the inline setup's PR context so both reason about the same PR.
  [[ -s "${SANDCAT_PR_CONTEXT_FILE}" ]] && extra_args+=(--pr-context "${SANDCAT_PR_CONTEXT_FILE}")

  echo "[INFO] sandcat: analyzing (sha=${SANDCAT_SHA:-unknown})..."
  local ok=true
  "${SANDCAT_BIN}" analyze \
    --ginkgo-report "${report}" \
    --sha "${SANDCAT_SHA}" \
    --source-dir "${source_dir}" \
    --agent \
    --upload "${SANDCAT_UPLOAD_URL}" \
    --timeout 10m \
    ${extra_args[@]+"${extra_args[@]}"} \
    || { ok=false; echo "[WARN] sandcat: analysis failed (non-fatal)"; }

  _sandcat_push_artifact
  [[ "${ok}" == "true" ]] && touch "${HOME}/.sandcat-analyzed"
  return 0
}

# Cap on what expanding a gzipped log may write to disk.
SANDCAT_MAX_LOG_BYTES="${SANDCAT_MAX_LOG_BYTES:-16777216}"

# Print candidate logs newest first, skipping the epilogue's own teardown logs.
# A phase killed early leaves an empty .gz as the newest file, so the caller
# walks the list until one has content.
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

# Keep the head (phase and config) and the tail (the failure) of an oversized log.
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
  # Over the cap and truncated: the tail is only of what could be recovered.
  if (( tail_rc != 0 )); then
    printf '\n[sandcat] this log is incomplete -- the compressed stream could not be read to the end, so anything after this point is missing\n' >> "${plain}"
  fi
  echo "[WARN] sandcat: ${log_file##*/} expands past ${SANDCAT_MAX_LOG_BYTES} bytes; analyzing its first ${head_bytes} and last ${tail_bytes}" >&2
}

# Print a plain-text path for the log, expanding gzip into a temp file; nothing
# when no content can be recovered. A truncated gzip keeps what came out.
_sandcat_plain_log() {
  local log_file="$1"
  # The gzip sniff below would call an empty file plain.
  [[ -r "${log_file}" && -s "${log_file}" ]] || return 1
  if [[ "$(head -c 2 "${log_file}" 2>/dev/null | od -An -tx1 | tr -d ' \n')" != "1f8b" ]]; then
    echo "${log_file}"
    return 0
  fi
  local plain
  plain=$(mktemp "${TMPDIR:-/tmp}/sandcat-build-log.XXXXXX") || return 1
  # head -c bounds the disk write and kills gzip with SIGPIPE, so gzip's status
  # only matters under the cap. One extra byte tells "exactly the cap" from "cut".
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

  # Only the expanded copy; an unexpanded log is the caller's file.
  if [[ -n "${plain_log}" && "${plain_log}" != "${log_file}" ]]; then
    _sandcat_rm_on_exit "${plain_log}"
  fi

  _sandcat_download || { echo "[WARN] sandcat: download failed; build failure not recorded"; return 0; }
  if [[ -n "${plain_log}" ]]; then
    echo "[INFO] sandcat: analyzing build failure from log (sha=${SANDCAT_SHA:-unknown})..."
    if "${SANDCAT_BIN}" analyze \
      --log-file "${plain_log}" \
      --sha "${SANDCAT_SHA}" \
      --source-dir "${source_dir}" \
      --timeout 10m; then
      _sandcat_push_artifact
      return 0
    fi
    echo "[WARN] sandcat: log analysis failed"
  fi

  echo "[INFO] sandcat: recording build failure without a log (sha=${SANDCAT_SHA:-unknown})"
  if "${SANDCAT_BIN}" analyze --build-failure \
    --sha "${SANDCAT_SHA}" \
    --source-dir "${source_dir}" \
    --timeout 10m; then
    _sandcat_push_artifact
  else
    echo "[WARN] sandcat: build failure not recorded (non-fatal)"
  fi
}

cmd_cut_off() {
  local source_dir="." after=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --source-dir) source_dir="$2"; shift 2 ;;
      --after)      after="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  SOURCE_DIR="${source_dir}"
  _sandcat_common_vars

  _sandcat_download || { echo "[WARN] sandcat: download failed; cut-off analysis not recorded"; return 0; }
  echo "[INFO] sandcat: recording that the analysis was stopped after ${after} (sha=${SANDCAT_SHA:-unknown})"
  "${SANDCAT_BIN}" analyze --cut-off-after "${after}" \
    --sha "${SANDCAT_SHA}" \
    --source-dir "${source_dir}" \
    --timeout 2m \
    || echo "[WARN] sandcat: cut-off analysis not recorded (non-fatal)"
}

# --- entry point ---
subcmd="${1:-}"
shift || true

# These subcommands need no ingest/upload tokens, so they run before that gate.
if [[ "${subcmd}" == "download" ]]; then
  _sandcat_download || exit 1
  echo "${SANDCAT_BIN}"
  exit 0
fi

if [[ "${subcmd}" == "fetch-pr" ]]; then
  cmd_fetch_pr || exit 1
  exit 0
fi

if [[ "${subcmd}" == "inline-env" ]]; then
  cmd_inline_env "$@" || exit 1
  exit 0
fi

if [[ "${subcmd}" == "download-calico-mcp" ]]; then
  _calico_mcp_download || exit 1
  echo "${CALICO_MCP_LOCAL_BIN}"
  exit 0
fi

if [[ "${subcmd}" == "push-specs" ]]; then
  cmd_push_specs "$@"
  exit 0
fi

if [[ -z "${SANDCAT_INGEST_TOKEN:-}" || -z "${SANDCAT_UPLOAD_URL:-}" ]]; then
  # A fork PR usually lacks the secret in the project's fork-PR allowlist.
  _sandcat_missing=""
  if [[ -z "${SANDCAT_INGEST_TOKEN:-}" ]]; then _sandcat_missing="SANDCAT_INGEST_TOKEN"; fi
  if [[ -z "${SANDCAT_UPLOAD_URL:-}" ]]; then _sandcat_missing="${_sandcat_missing:+${_sandcat_missing} }SANDCAT_UPLOAD_URL"; fi
  echo "[INFO] sandcat: skipping '${subcmd}' — unset: ${_sandcat_missing}" >&2
  exit 0
fi

case "${subcmd}" in
  analyze)       cmd_analyze "$@" ;;
  build-failure) cmd_build_failure "$@" ;;
  cut-off)       cmd_cut_off "$@" ;;
  *)             echo "[ERROR] sandcat.sh: unknown subcommand '${subcmd}'" >&2; exit 1 ;;
esac
