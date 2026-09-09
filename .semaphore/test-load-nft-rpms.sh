#!/usr/bin/env bash
# Smoke tests for load-nft-rpms.sh, covering the Docker Hub fallback that keeps
# a credential-less (read-only) build going when the S3 tarball is missing.
# Not run in CI; run manually:
#   .semaphore/test-load-nft-rpms.sh
#
# docker, make, zstd and curl are stubbed on PATH, so nothing is pulled, built
# or fetched: the stubs record their argv to $stub_log. The real s3-cmd runs,
# with no credentials, so its anonymous-read path goes through the curl stub.
set -u
cd "$(dirname "$0")/.." || exit 1
loader="$PWD/.semaphore/scripts/load-nft-rpms.sh"
fails=0

check() {
  local desc="$1"
  shift
  if "$@"; then echo "PASS: $desc"; else
    echo "FAIL: $desc"
    fails=$((fails + 1))
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
stub_dir="$work/bin"
stub_log="$work/calls.log"
mkdir -p "$stub_dir"

# IMAGE_PRESENT makes `docker image inspect` succeed; PULL_FAIL makes
# `docker pull` fail the way an unpublished tag would.
cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >>"$STUB_LOG"
case "$1 ${2:-}" in
  "image inspect") [[ -n "${IMAGE_PRESENT:-}" ]] || exit 1 ;;
  "pull "*) [[ -z "${PULL_FAIL:-}" ]] || exit 1 ;;
esac
exit 0
STUB

cat >"$stub_dir/make" <<'STUB'
#!/usr/bin/env bash
echo "make $*" >>"$STUB_LOG"
echo "testtag"
STUB

# `zstd -d --rm <file>.zst` decompresses in place; the stub just renames.
cat >"$stub_dir/zstd" <<'STUB'
#!/usr/bin/env bash
echo "zstd $*" >>"$STUB_LOG"
for a in "$@"; do [[ "$a" == *.zst ]] && mv "$a" "${a%.zst}"; done
exit 0
STUB

cat >"$stub_dir/curl" <<'STUB'
#!/usr/bin/env bash
echo "curl $*" >>"$STUB_LOG"
[[ -n "${CURL_FAIL:-}" ]] && exit 22
prev=""
for a in "$@"; do
  [[ "$prev" == "-o" ]] && echo tarball >"$a"
  prev="$a"
done
exit 0
STUB

chmod +x "$stub_dir"/*
export PATH="$stub_dir:$PATH" STUB_LOG="$stub_log"
export CALICO_S3_HOST=s3.example.com S3_WORKFLOW_DIR=s3://test-bucket/ci/workflow/1
unset CALICO_S3_ACCESS_KEY CALICO_S3_SECRET_KEY

run() {
  : >"$stub_log"
  rm -f /tmp/nft-rpms.tar /tmp/nft-rpms.tar.zst
  "$loader" "$@"
}

# 1. Tarball available: load it, and do not fall back to a pull.
out=$(run amd64 2>&1)
rc=$?
check "tarball load RC=0" [ "$rc" = 0 ]
check "tarball fetched over S3" grep -q "^curl .*nft-rpms-amd64.tar.zst" "$stub_log"
check "tarball loaded into docker" grep -q "^docker load -i /tmp/nft-rpms.tar" "$stub_log"
check "no Docker Hub pull" test "$(grep -c '^docker pull ' "$stub_log")" = 0

# 2. No tarball (the read-only case: the producer's upload was skipped): fall
#    back to pulling the published image.
out=$(CURL_FAIL=1 run amd64 2>&1)
rc=$?
check "fallback RC=0" [ "$rc" = 0 ]
check "fallback pulls image" grep -q "^docker pull calico/nftables-rpms:testtag-amd64" "$stub_log"
check "fallback does not docker load" test "$(grep -c '^docker load ' "$stub_log")" = 0

# 3. Neither source has it: fail, with an error naming the cause.
out=$(CURL_FAIL=1 PULL_FAIL=1 run arm64 2>&1)
rc=$?
check "no source available fails" [ "$rc" != 0 ]
check "no source available explains why" grep -q "neither the S3 workflow cache nor Docker Hub" <<<"$out"

# 4. Image already loaded locally: skip both the fetch and the pull.
out=$(IMAGE_PRESENT=1 run amd64 2>&1)
rc=$?
check "already-present RC=0" [ "$rc" = 0 ]
check "already-present skips fetch" test "$(grep -c '^curl ' "$stub_log")" = 0
check "already-present skips pull" test "$(grep -c '^docker pull ' "$stub_log")" = 0

# 5. Arch is required.
run >/dev/null 2>&1
check "missing arch fails" [ "$?" != 0 ]

echo "FAILURES: $fails"
exit $fails
