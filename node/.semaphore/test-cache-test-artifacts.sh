#!/usr/bin/env bash
# Smoke tests for node/.semaphore/cache-test-artifacts, focused on the local
# build+save that supplies the calico, node and whisker images when the S3
# workflow cache is empty — load-test-artifacts on the test VM cannot build
# them there.
# Not run in CI; run manually:
#   node/.semaphore/test-cache-test-artifacts.sh
#
# docker, gcloud, make, zstd, tar, curl and s3cmd are stubbed on PATH, so
# nothing is built, saved, uploaded or fetched: the stubs record their argv to
# $stub_log. The real s3-cmd and load-cached-images run on top of them, and
# CURL_FAIL / S3CMD_FAIL simulate an empty cache.
set -u
node_dir="$(cd "$(dirname "$0")/.." && pwd)"
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

for tool in docker gcloud make tar; do
  cat >"$stub_dir/$tool" <<STUB
#!/usr/bin/env bash
echo "$tool \$*" >>"\$STUB_LOG"
exit 0
STUB
done

# \`zstd -3 --rm <file>\` compresses in place; the stub just renames.
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

images=(calico node whisker)

run() {
  : >"$stub_log"
  for img in "${images[@]}"; do rm -f "/tmp/${img}-image.tar" "/tmp/${img}-image.tar.zst"; done
  (cd "$node_dir" && "$node_dir/.semaphore/cache-test-artifacts") >/dev/null 2>&1
}

# 1. Credential-less build, empty cache: build each image from source through
#    load-cached-images, save it out of the local daemon, and still publish it
#    to GCS for the test VM.
unset CALICO_S3_ACCESS_KEY CALICO_S3_SECRET_KEY
CURL_FAIL=1 run
rc=$?
check "read-only miss RC=0" [ "$rc" = 0 ]
for img in "${images[@]}"; do
  check "read-only miss builds ${img} image" grep -q "${img}/.image.created-amd64" "$stub_log"
  check "read-only miss saves local ${img} image" grep -q "^docker save calico/${img}:latest-amd64 -o /tmp/${img}-image.tar\$" "$stub_log"
  check "read-only miss compresses ${img}" grep -q "^zstd -3 --rm /tmp/${img}-image.tar\$" "$stub_log"
  check "read-only miss uploads ${img} to GCS" grep -q "^gcloud storage cp /tmp/${img}-image.tar.zst gs://" "$stub_log"
done

# 2. Cache hit: use the downloaded tarballs, build and save nothing.
export CALICO_S3_ACCESS_KEY=AKID CALICO_S3_SECRET_KEY=SECRET
run
rc=$?
check "cache hit RC=0" [ "$rc" = 0 ]
check "cache hit downloads from S3" grep -q "^s3cmd .* get --force " "$stub_log"
check "cache hit builds nothing" test "$(grep -c '\.image\.created' "$stub_log")" = 0
check "cache hit saves nothing" test "$(grep -c '^docker save ' "$stub_log")" = 0
for img in "${images[@]}"; do
  check "cache hit uploads ${img} to GCS" grep -q "^gcloud storage cp /tmp/${img}-image.tar.zst gs://" "$stub_log"
done

for img in "${images[@]}"; do rm -f "/tmp/${img}-image.tar" "/tmp/${img}-image.tar.zst"; done
echo "FAILURES: $fails"
exit $fails
