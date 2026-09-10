#!/usr/bin/env bash
# Smoke tests for load-cached-images and load-felix-prereqs.sh, focused on the
# build-from-source fallback that keeps a credential-less (read-only) build
# going when the workflow cache is empty.
# Not run in CI; run manually:
#   .semaphore/test-load-cached-images.sh
#
# make, docker, zstd, tar, curl and s3cmd are stubbed on PATH, so nothing is
# built, loaded or fetched: the stubs record their argv to $stub_log. The real
# s3-cmd runs on top of them — its anonymous-read path uses curl, its
# credentialed path s3cmd — and CURL_FAIL / S3CMD_FAIL simulate an empty cache.
set -u
cd "$(dirname "$0")/.." || exit 1
repo_root="$PWD"
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

for tool in make docker zstd tar; do
  cat >"$stub_dir/$tool" <<STUB
#!/usr/bin/env bash
echo "$tool \$*" >>"\$STUB_LOG"
exit 0
STUB
done

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

# The credentialed paths go through s3cmd rather than curl; `get` has to
# produce the destination file its caller then uses.
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
unset CALICO_S3_ACCESS_KEY CALICO_S3_SECRET_KEY

run() {
  : >"$stub_log"
  "$@"
}

# 1. Credential-less build, empty cache: only the requested components are
#    built from source, through their .image.created marker rules.
out=$(CURL_FAIL=1 run "$repo_root/.semaphore/load-cached-images" calico 2>&1)
rc=$?
check "read-only miss RC=0" [ "$rc" = 0 ]
check "read-only miss builds calico" grep -q "^make -C ${repo_root} ${repo_root}/cmd/calico/.image.created-amd64" "$stub_log"
check "read-only miss skips node" test "$(grep -c 'node/.image.created' "$stub_log")" = 0
check "read-only miss skips whisker" test "$(grep -c 'whisker/.image.created' "$stub_log")" = 0
check "read-only miss says so" grep -q "credential-less build" <<<"$out"

# 2. A requested node image goes through load-nft-rpms.sh before building, so
#    the node build does not produce the RPMs image from scratch.
CURL_FAIL=1 run "$repo_root/.semaphore/load-cached-images" node >/dev/null 2>&1
check "node build loads nft-rpms first" grep -q "^docker image inspect calico/nftables-rpms" "$stub_log"
check "node build runs marker rule" grep -q "node/.image.created-amd64" "$stub_log"

# 3. Cache hit: load the tarball and do not build anything.
out=$(run "$repo_root/.semaphore/load-cached-images" calico 2>&1)
rc=$?
check "cache hit RC=0" [ "$rc" = 0 ]
check "cache hit loads image" grep -q "^docker load " "$stub_log"
check "cache hit builds nothing" test "$(grep -c '^make ' "$stub_log")" = 0

# 4. With credentials, a miss is tolerated and nothing is built — unchanged
#    behaviour, since the producer block simply may not have run.
out=$(CALICO_S3_ACCESS_KEY=AKID CALICO_S3_SECRET_KEY=SECRET S3CMD_FAIL=1 \
  run "$repo_root/.semaphore/load-cached-images" calico 2>&1)
rc=$?
check "credentialed miss RC=0" [ "$rc" = 0 ]
check "credentialed miss builds nothing" test "$(grep -c '^make ' "$stub_log")" = 0
check "credentialed miss reports the miss" grep -q "No cached calico/calico image found" <<<"$out"

# 5. Felix prereqs, credential-less: libbpf and the cgo/race binaries are built
#    rather than downloaded, and the libbpf clone guard is dropped for it.
#    The stubbed make produces no artifacts, so pre-create what the script
#    checks for and chmods, and remove only what this test created.
mkdir -p "$repo_root/felix/bpf-gpl/libbpf/src/amd64" "$repo_root/cmd/calico/bin"
libbpf_a="$repo_root/felix/bpf-gpl/libbpf/src/amd64/libbpf.a"
created_libbpf=false
if [ ! -f "$libbpf_a" ]; then
  touch "$libbpf_a"
  created_libbpf=true
fi
created_bins=()
for bin in "$repo_root/cmd/calico/bin/calico-cgo-amd64" "$repo_root/cmd/calico/bin/calico-race-amd64"; do
  if [ ! -f "$bin" ]; then
    touch "$bin"
    created_bins+=("$bin")
  fi
done
trap '[ ${#created_bins[@]} -eq 0 ] || rm -f "${created_bins[@]}"; rm -rf "$work"' EXIT
out=$(NO_LIBBPF_CLONE=true run "$repo_root/.semaphore/scripts/load-felix-prereqs.sh" 2>&1)
rc=$?
check "felix prereqs RC=0" [ "$rc" = 0 ]
check "felix prereqs build libbpf" grep -q "^make -C felix libbpf ARCH=amd64" "$stub_log"
check "felix prereqs build cgo and race" grep -q "^make -C cmd/calico build-cgo build-race ARCH=amd64" "$stub_log"
check "felix prereqs do not download" test "$(grep -c '^curl ' "$stub_log")" = 0

# 6. Felix prereqs with credentials: download, do not build.
out=$(CALICO_S3_ACCESS_KEY=AKID CALICO_S3_SECRET_KEY=SECRET \
  run "$repo_root/.semaphore/scripts/load-felix-prereqs.sh" 2>&1)
rc=$?
check "felix prereqs credentialed RC=0" [ "$rc" = 0 ]
check "felix prereqs credentialed build nothing" test "$(grep -c '^make ' "$stub_log")" = 0

# 7. Missing libbpf.a after the fetch is a hard error, not a silent pass.
$created_libbpf && rm -f "$libbpf_a"
if [ ! -f "$libbpf_a" ]; then
  out=$(run "$repo_root/.semaphore/scripts/load-felix-prereqs.sh" 2>&1)
  check "missing libbpf.a fails" [ "$?" != 0 ]
  check "missing libbpf.a explains why" grep -q "missing its compiled" <<<"$out"
else
  echo "SKIP: missing libbpf.a case (a real libbpf.a is present in the tree)"
fi

echo "FAILURES: $fails"
exit $fails
