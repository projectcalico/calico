#!/usr/bin/env bash
# Behaviour test for with-inline-diag.sh: the wrapper must never be the reason a
# job fails.
#
# It sits between the cluster coming up and the conformance suite starting, so
# anything it lets escape costs the whole run -- the tests never execute, and
# the failure looks nothing like "sandcat could not diagnose". That has already
# happened once: an unredirected stdout write from `check-mcp` reached the
# KEY=VALUE payload, was eval'd as a command, and under `set -e` took the phase
# down after the cluster had been provisioned. So the property under test is not
# "the exports are right" but "the wrapped command runs, whatever happened".
#
# Exercised under `set -eo pipefail`, the way the e2e phase scripts run.

set -uo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WRAPPER="${DIR}/with-inline-diag.sh"
REPO_ROOT=$(cd "${DIR}/../../.." && pwd)
pass=0
fail=0

# run <name> <want_marker_present> -- runs the wrapper around a marker command in
# a clean environment, and reports whether the marker made it out with rc=0.
run() {
  local name="$1"
  shift
  local out rc
  out=$(env -i PATH="/usr/bin:/bin" HOME="${HOME}" KUBECONFIG=/tmp/kubeconfig \
    CALICO_MCP_LOCAL_BIN="${CALICO_MCP_LOCAL_BIN}" \
    SANDCAT_PR_CONTEXT_FILE="${SANDCAT_PR_CONTEXT_FILE}" \
    "$@" \
    bash -eo pipefail -c "'${WRAPPER}' echo WRAPPED-COMMAND-RAN" 2>&1)
  rc=$?
  if [[ "${rc}" == 0 ]] && grep -qF WRAPPED-COMMAND-RAN <<<"${out}"; then
    echo "PASS ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name} (rc=${rc})"
    sed 's/^/    /' <<<"${out}"
    fail=$((fail + 1))
  fi
}

newhome() {
  HOME=$(mktemp -d)
  export HOME
  mkdir -p "${HOME}/.local/bin"
  CALICO_MCP_LOCAL_BIN="${HOME}/.local/bin/calico-mcp"
  export CALICO_MCP_LOCAL_BIN
  SANDCAT_PR_CONTEXT_FILE="${HOME}/pr-context.json"
  export SANDCAT_PR_CONTEXT_FILE
  printf '#!/bin/sh\necho "calico-mcp 0.0-stub"\n' > "${CALICO_MCP_LOCAL_BIN}"
  chmod +x "${CALICO_MCP_LOCAL_BIN}"
}

# The success path still has to pass the command through -- a wrapper that
# swallowed it would look identical to one that failed to set anything up.
newhome
cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  # As chatty on stdout as the real one: this is what must not reach the eval.
  check-mcp) echo "calico-mcp ok: 18 tools registered, cluster answered"; exit 0 ;;
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
run "everything set up" SANDCAT_GEMINI_KEY=key-a

# The ordinary local case, and any job not granted a key.
newhome
run "no Gemini key"

# A refusal: the hook is off, the suite still runs.
newhome
cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == "check-mcp" ]] && exit 3
exit 1
STUB
chmod +x "${HOME}/.local/bin/sandcat"
run "calico-mcp refused" SANDCAT_GEMINI_KEY=key-a

# No binary to download and no credentials to fetch one with.
newhome
run "sandcat binary unavailable" SANDCAT_GEMINI_KEY=key-a

# The regression that motivated this file: a stray line on the payload stream.
# It must degrade to "no diagnosis", never to a dead job.
newhome
cat > "${HOME}/.local/bin/sandcat" <<'STUB'
#!/usr/bin/env bash
echo "surprise: not an assignment; and (unbalanced"
exit 0
STUB
chmod +x "${HOME}/.local/bin/sandcat"
run "sandcat writes junk to stdout" SANDCAT_GEMINI_KEY=key-a

# `exec` with no arguments succeeds and runs nothing, so a wrapper that lost its
# command would report a green job that executed no tests. It has to be loud.
newhome
if env -i PATH="/usr/bin:/bin" HOME="${HOME}" KUBECONFIG=/tmp/kubeconfig \
    bash -eo pipefail -c "'${WRAPPER}'" >/dev/null 2>&1; then
  echo "FAIL no command: exited 0 having run nothing"
  fail=$((fail + 1))
else
  echo "PASS no command: refuses instead of silently succeeding"
  pass=$((pass + 1))
fi

# A wrapper only helps where it is applied. e2e-test-bpf shipped without the
# prefix and lost every inline diagnosis in that lane, with nothing failing to
# say so, so assert each kind e2e target still carries it.
recipe_of() {
  awk -v target="$1" '
    $0 ~ "^"target":" { in_recipe = 1; next }
    in_recipe && /^\t/ { print; next }
    in_recipe && NF && !/^#/ { exit }
  ' "${REPO_ROOT}/Makefile"
}

for target in e2e-test e2e-test-bpf; do
  if recipe_of "${target}" | grep -qF 'E2E_RUN_WRAPPER'; then
    echo "PASS ${target} applies \$(E2E_RUN_WRAPPER)"
    pass=$((pass + 1))
  else
    echo "FAIL ${target} does not apply \$(E2E_RUN_WRAPPER): inline diagnosis is off in that lane"
    fail=$((fail + 1))
  fi
done

echo "=== ${pass} passed, ${fail} failed"
[[ "${fail}" == 0 ]]
