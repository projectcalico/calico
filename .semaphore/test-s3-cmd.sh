#!/usr/bin/env bash
# Smoke tests for s3-cmd, focused on the credential-less (read-only) fallback.
# Not run in CI; run manually:
#   .semaphore/test-s3-cmd.sh
#
# s3cmd and curl are stubbed on PATH, so no network access or real bucket is
# needed: the stubs record their argv to $stub_log and serve canned responses.
set -u
cd "$(dirname "$0")" || exit 1
s3_cmd="$PWD/s3-cmd"
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

# The s3cmd stub records its argv and, for `ls`, replays $S3CMD_LS_OUT as the
# listing so the wrapper's output massaging can be checked.
cat >"$stub_dir/s3cmd" <<'STUB'
#!/usr/bin/env bash
echo "s3cmd $*" >>"$STUB_LOG"
for a in "$@"; do
  if [[ "$a" == ls && -n "${S3CMD_LS_OUT:-}" ]]; then
    printf '%s\n' "$S3CMD_LS_OUT"
    break
  fi
done
exit 0
STUB

# The curl stub understands just enough of the flags s3-cmd passes: -o writes
# the canned body to that path, otherwise the body goes to stdout. Setting
# CURL_FAIL makes it behave like `curl -f` against a 404.
cat >"$stub_dir/curl" <<'STUB'
#!/usr/bin/env bash
echo "curl $*" >>"$STUB_LOG"
out=""
prev=""
for a in "$@"; do
  [[ "$prev" == "-o" ]] && out="$a"
  prev="$a"
done
[[ -n "${CURL_FAIL:-}" ]] && exit 22
if [[ -n "$out" ]]; then echo "${CURL_BODY:-body}" >"$out"; else echo "${CURL_BODY:-body}"; fi
STUB

chmod +x "$stub_dir/s3cmd" "$stub_dir/curl"
export PATH="$stub_dir:$PATH" STUB_LOG="$stub_log"
export CALICO_S3_BUCKET=test-bucket CALICO_S3_HOST=s3.example.com
export CALICO_S3_KEY_PREFIX=ci CALICO_S3_EXPIRY_DAYS=7

run() { : >"$stub_log"; "$s3_cmd" "$@"; }

# 1. No credentials: an upload is skipped, exits 0, and never invokes s3cmd.
unset CALICO_S3_ACCESS_KEY CALICO_S3_SECRET_KEY
echo payload >"$work/upload.bin"
out=$(run cp "$work/upload.bin" s3://test-bucket/ci/workflow/x.tar.zst 2>&1)
rc=$?
check "no-creds upload RC=0" [ "$rc" = 0 ]
check "no-creds upload logs skip" grep -q "skipping upload" <<<"$out"
check "no-creds upload does not call s3cmd" test ! -s "$stub_log"

# 2. No credentials: a download falls back to an anonymous HTTPS GET of the
#    public URL built from CALICO_S3_HOST.
out=$(run cp s3://test-bucket/ci/workflow/x.tar.zst "$work/got.bin" 2>&1)
rc=$?
check "no-creds download RC=0" [ "$rc" = 0 ]
check "no-creds download uses curl" grep -q "^curl " "$stub_log"
check "no-creds download URL" grep -q "https://test-bucket.s3.example.com/ci/workflow/x.tar.zst" "$stub_log"
check "no-creds download wrote file" test -s "$work/got.bin"
check "no-creds download does not call s3cmd" test "$(grep -c '^s3cmd ' "$stub_log")" = 0

# 3. A missing object in read-only mode fails, so callers can fall back to
#    building from source rather than loading a truncated file. curl creates the
#    output file before it sees the response, so the empty one it leaves behind
#    must go too: callers test for the file, or decompress into a path derived
#    from it (where a stale .zst would make zstd refuse to overwrite).
: >"$work/missing.bin"
CURL_FAIL=1 run cp s3://test-bucket/ci/missing.tar.zst "$work/missing.bin" >/dev/null 2>&1
rc=$?
check "no-creds download of missing object fails" [ "$rc" != 0 ]
check "no-creds download of missing object leaves no file" test ! -e "$work/missing.bin"

# 4. CALICO_S3_HOST_BUCKET overrides the origin (path-style endpoints).
out=$(CALICO_S3_HOST_BUCKET=s3.example.com/%\(bucket\)s run cp \
  s3://test-bucket/ci/x.tar.zst "$work/got2.bin" 2>&1)
check "host-bucket template honoured" grep -q "https://s3.example.com/test-bucket/ci/x.tar.zst" "$stub_log"

# 5. No credentials: ls hits ListObjectsV2 and prints matching keys; an empty
#    listing exits non-zero, matching the credentialed path.
CURL_BODY='<ListBucketResult><Contents><Key>ci/a.tar</Key></Contents><Contents><Key>ci/b.tar</Key></Contents></ListBucketResult>'
out=$(CURL_BODY="$CURL_BODY" run ls s3://test-bucket/ci/ 2>/dev/null)
rc=$?
check "no-creds ls RC=0 with matches" [ "$rc" = 0 ]
check "no-creds ls lists keys" test "$out" = "s3://test-bucket/ci/a.tar
s3://test-bucket/ci/b.tar"
CURL_BODY='<ListBucketResult></ListBucketResult>' run ls s3://test-bucket/ci/ >/dev/null 2>&1
check "no-creds ls RC!=0 when empty" [ "$?" != 0 ]

# 6. With credentials, both directions still go through s3cmd, and uploads keep
#    carrying the expiry header.
export CALICO_S3_ACCESS_KEY=AKID CALICO_S3_SECRET_KEY=SECRET
out=$(run cp "$work/upload.bin" s3://test-bucket/ci/x.tar.zst 2>&1)
rc=$?
check "creds upload RC=0" [ "$rc" = 0 ]
check "creds upload calls s3cmd put" grep -q "^s3cmd .* put " "$stub_log"
check "creds upload passes access key" grep -q -- "--access_key=AKID" "$stub_log"
check "creds upload passes expiry" grep -q -- "--add-header=Expires:" "$stub_log"
check "creds upload does not use curl" test "$(grep -c '^curl ' "$stub_log")" = 0

run cp s3://test-bucket/ci/x.tar.zst "$work/got3.bin" >/dev/null 2>&1
check "creds download calls s3cmd get" grep -q "^s3cmd .* get --force " "$stub_log"

# 7. With credentials, ls strips s3cmd's date/size (and DIR) columns so its
#    output matches the anonymous path: one bare s3:// URL per line.
S3CMD_LS_OUT='2026-08-12 22:22          1234  s3://test-bucket/ci/a.tar
                       DIR  s3://test-bucket/ci/sub/'
out=$(S3CMD_LS_OUT="$S3CMD_LS_OUT" run ls s3://test-bucket/ci/ 2>/dev/null)
rc=$?
check "creds ls RC=0 with matches" [ "$rc" = 0 ]
check "creds ls prints bare URLs" test "$out" = "s3://test-bucket/ci/a.tar
s3://test-bucket/ci/sub/"
run ls s3://test-bucket/ci/ >/dev/null 2>&1
check "creds ls RC!=0 when empty" [ "$?" != 0 ]

# 8. A half-set credential pair counts as no credentials, rather than sending a
#    request that would be rejected as an invalid signature.
unset CALICO_S3_SECRET_KEY
out=$(run cp "$work/upload.bin" s3://test-bucket/ci/x.tar.zst 2>&1)
check "partial creds treated as read-only" grep -q "skipping upload" <<<"$out"

# 9. write-config without credentials still writes the endpoint and warns.
unset CALICO_S3_ACCESS_KEY
out=$(run write-config "$work/s3cfg" 2>&1)
rc=$?
check "no-creds write-config RC=0" [ "$rc" = 0 ]
check "no-creds write-config warns" grep -q "wrote .* without them" <<<"$out"
check "no-creds write-config has host" grep -q "host_base = s3.example.com" "$work/s3cfg"

echo "FAILURES: $fails"
exit $fails
