#!/usr/bin/env bash
# Smoke tests for felix/.semaphore/cache-test-artifacts, focused on the local
# save that supplies the calico image when the S3 workflow cache is empty —
# load-test-artifacts on the test VM needs that tarball unconditionally.
# Not run in CI; run manually:
#   felix/.semaphore/test-cache-test-artifacts.sh
#
# artifact, docker, gcloud, zstd, tar, curl and s3cmd are stubbed on PATH, so
# nothing is saved, uploaded or fetched: the stubs record their argv to
# $stub_log. The real s3-cmd runs on top of them, and CURL_FAIL / S3CMD_FAIL
# simulate an empty cache.
set -u
felix_dir="$(cd "$(dirname "$0")/.." && pwd)"
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

for tool in artifact docker gcloud tar; do
  cat >"$stub_dir/$tool" <<STUB
#!/usr/bin/env bash
echo "$tool \$*" >>"\$STUB_LOG"
exit 0
STUB
done

# `zstd -3 --rm <file>` compresses in place; the stub just renames.
cat >"$stub_dir/zstd" <<'STUB'
#!/usr/bin/env bash
echo "zstd $*" >>"$STUB_LOG"
for a in "$@"; do [[ "$a" == /* && "$a" != *.zst ]] && mv "$a" "$a.zst"; done
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

cat >"$stub_dir/s3cmd" <<'STUB'
#!/usr/bin/env bash
echo "s3cmd $*" >>"$STUB_LOG"
[[ -n "${S3CMD_FAIL:-}" ]] && exit 1
if [[ " $* " == *" get "* ]]; then echo body >"${*: -1}"; fi
exit 0
STUB

chmod +x "$stub_dir"/*
export PATH="$stub_dir:$PATH" STUB_LOG="$stub_log"
export CALICO_S3_HOST=s3.example.com S3_WORKFLOW_DIR=s3://test-bucket/ci/workflow/1
export GCS_WORKFLOW_DIR=gs://test-bucket/workflow/1 CALICO_DIR_NAME=calico

run() {
  : >"$stub_log"
  rm -f /tmp/calico-image.tar /tmp/calico-image.tar.zst
  (cd "$felix_dir" && "$felix_dir/.semaphore/cache-test-artifacts") >/dev/null 2>&1
}

# 1. Credential-less build, empty cache: save the calico image out of the local
#    daemon, and still publish it to GCS for the test VM.
unset CALICO_S3_ACCESS_KEY CALICO_S3_SECRET_KEY
CURL_FAIL=1 run
rc=$?
check "read-only miss RC=0" [ "$rc" = 0 ]
check "read-only miss saves local calico image" grep -q "^docker save -o /tmp/calico-image.tar calico/calico:latest-amd64" "$stub_log"
check "read-only miss compresses it" grep -q "^zstd -3 --rm /tmp/calico-image.tar" "$stub_log"
check "read-only miss still uploads to GCS" grep -q "^gcloud storage cp /tmp/calico-image.tar.zst gs://" "$stub_log"

# 2. Cache hit: use the downloaded tarball, do not re-save the image.
export CALICO_S3_ACCESS_KEY=AKID CALICO_S3_SECRET_KEY=SECRET
run
rc=$?
check "cache hit RC=0" [ "$rc" = 0 ]
check "cache hit downloads from S3" grep -q "^s3cmd .* get --force " "$stub_log"
check "cache hit does not save calico image" test "$(grep -c 'docker save -o /tmp/calico-image.tar ' "$stub_log")" = 0
check "cache hit uploads to GCS" grep -q "^gcloud storage cp /tmp/calico-image.tar.zst gs://" "$stub_log"

# 3. The felix-test image is saved either way — it is this job's own output.
check "felix-test image always saved" grep -q "^docker save -o /tmp/calico-felix-test.tar calico/felix-test:latest-amd64" "$stub_log"

rm -f /tmp/calico-image.tar /tmp/calico-image.tar.zst
echo "FAILURES: $fails"
exit $fails
