#!/usr/bin/env bash
# Tests publish-pr-context and fetch-pr sharing one PR context through a stubbed workflow artifact store.

set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandcat.sh}"
pass=0
fail=0
homes=()
trap 'rm -rf ${homes[@]+"${homes[@]}"}' EXIT

newhome() {
  HOME=$(mktemp -d)
  export HOME
  homes+=("${HOME}")
  mkdir -p "${HOME}/.local/bin" "${HOME}/bin" "${HOME}/store"
  # fetch-pr writes a context only on a PR run, and records the token it saw.
  cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == "fetch-pr" ]] || exit 0
echo "${GITHUB_ACCESS_TOKEN:-}" > "${HOME}/fetch-token"
[[ "${STUB_PR:-1}" == 1 ]] || exit 0
while [[ $# -gt 0 ]]; do
  [[ "$1" == "--out" ]] && echo '{"body":"fetched"}' > "$2"
  shift
done
STUB
  chmod +x "${HOME}/.local/bin/sandcat"
  # artifact push|pull workflow SRC --destination DST, backed by ${HOME}/store.
  cat > "${HOME}/bin/artifact" <<'STUB'
#!/usr/bin/env bash
op="$1" src="$3" dst="$5"
case "${op}" in
  push) cp "${src}" "${HOME}/store/${dst}" ;;
  pull) cp "${HOME}/store/${src}" "${dst}" 2>/dev/null ;;
esac
STUB
  chmod +x "${HOME}/bin/artifact"
  PATH="${HOME}/bin:/usr/bin:/bin"
  export PATH
  unset CI_WORKFLOW_NAME SANDCAT_PR_READ_TOKEN STUB_PR
}

check() {
  local name="$1" ok="$2"
  if [[ "${ok}" == 0 ]]; then
    echo "PASS ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name}"
    fail=$((fail + 1))
  fi
}

newhome
SANDCAT_PR_READ_TOKEN=read-only "${SCRIPT}" publish-pr-context >/dev/null 2>&1
grep -qF fetched "${HOME}/store/sandcat-pr-context.json" 2>/dev/null
check "publish-pr-context pushes the PR context for the workflow" $?
ok=1
[[ "$(cat "${HOME}/fetch-token")" == read-only ]] && ok=0
check "publish-pr-context reads the PR with SANDCAT_PR_READ_TOKEN" "${ok}"

newhome
STUB_PR=0 "${SCRIPT}" publish-pr-context >/dev/null 2>&1
rc=$?
ok=1
[[ "${rc}" == 0 && ! -e "${HOME}/store/sandcat-pr-context.json" ]] && ok=0
check "publish-pr-context on a branch run pushes nothing and succeeds" "${ok}"

newhome
echo '{"body":"published"}' > "${HOME}/store/sandcat-pr-context.json"
out=$(CI_WORKFLOW_NAME=wf "${SCRIPT}" fetch-pr 2>/dev/null)
[[ -n "${out}" ]] && grep -qF published "${out}" && [[ ! -e "${HOME}/fetch-token" ]]
check "fetch-pr on ArgoCI uses the published context without fetching" $?

newhome
out=$(CI_WORKFLOW_NAME=wf "${SCRIPT}" fetch-pr 2>/dev/null)
[[ -n "${out}" ]] && grep -qF fetched "${out}"
check "fetch-pr fetches itself when nothing was published" $?

newhome
echo '{"body":"published"}' > "${HOME}/store/sandcat-pr-context.json"
out=$("${SCRIPT}" fetch-pr 2>/dev/null)
[[ -n "${out}" ]] && grep -qF fetched "${out}"
check "fetch-pr off ArgoCI ignores the artifact store" $?

newhome
STUB_PR=0 CI_WORKFLOW_NAME=wf "${SCRIPT}" fetch-pr >/dev/null 2>&1
[[ $? != 0 && ! -e "${HOME}/sandcat-pr-context.json" ]]
check "fetch-pr on a branch run prints nothing and fails" $?

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
