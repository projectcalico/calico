#!/usr/bin/env bash
# Behaviour test for `sandcat.sh download`: the GitHub token authenticates both
# requests but never appears in curl's arguments. curl is stubbed, so no network
# is needed.

set -uo pipefail

SCRIPT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sandcat.sh}"
pass=0
fail=0

HOME=$(mktemp -d)
export HOME
trap 'rm -rf "${HOME}"' EXIT
mkdir -p "${HOME}/bin"
cat > "${HOME}/bin/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${HOME}/argv"
cat >> "${HOME}/config"
out=""
while [[ $# -gt 0 ]]; do
  [[ "$1" == "-o" ]] && out="$2"
  shift
done
if [[ -n "${out}" ]]; then
  printf '#!/bin/sh\n' > "${out}"
else
  echo '{"assets":[{"name":"sandcat-linux-amd64","url":"https://api.github.com/asset/1"}]}'
fi
STUB
chmod +x "${HOME}/bin/curl"
export PATH="${HOME}/bin:${PATH}"
export GITHUB_ACCESS_TOKEN=secret-token-value

check() {
  local name="$1"
  shift
  if "$@"; then
    echo "PASS ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name}"
    fail=$((fail + 1))
  fi
}

bin=$("${SCRIPT}" download 2>/dev/null)
check "download prints the binary path" test "${bin}" = "${HOME}/.local/bin/sandcat"
check "the binary is executable" test -x "${HOME}/.local/bin/sandcat"
check "both requests were made" test "$(wc -l < "${HOME}/argv")" -eq 2
check "the token is not in curl's arguments" bash -c "! grep -qF secret-token-value '${HOME}/argv'"
check "both requests carry the token" \
  test "$(grep -cF 'header = "Authorization: token secret-token-value"' "${HOME}/config")" -eq 2

echo "${pass} passed, ${fail} failed"
[[ "${fail}" -eq 0 ]]
