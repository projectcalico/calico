#!/usr/bin/env bash
# Smoke tests for .semaphore/vms/batch-memo.
# Not run in CI; run manually:
#   .semaphore/vms/test-batch-memo.sh
#
# `artifact` is stubbed on PATH: its cache lives in a local directory and
# `pull workflow` serves a plan written by the test.
set -u
vms_dir="$(cd "$(dirname "$0")" && pwd)"
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
mkdir -p "$work/bin" "$work/cache" "$work/workflow"
export STUB_CACHE="$work/cache" STUB_WORKFLOW="$work/workflow"
cat >"$work/bin/artifact" <<'STUB'
#!/usr/bin/env bash
set -e
case "$1 $2" in
  "cache store")
    key="$3"; shift 3
    mkdir -p "$(dirname "$STUB_CACHE/$key")"
    tar -cf "$STUB_CACHE/$key" -- "$@" ;;
  "cache restore")
    [ -f "$STUB_CACHE/$3" ] && tar -xf "$STUB_CACHE/$3" || echo "MISS $3" ;;
  "cache has_key")
    [ -f "$STUB_CACHE/$3" ] ;;
  "pull workflow")
    [ -e "$STUB_WORKFLOW/$3" ] && cp -r "$STUB_WORKFLOW/$3" . ;;
  *) echo "unexpected: artifact $*" >&2; exit 1 ;;
esac
STUB
chmod +x "$work/bin/artifact"
export PATH="$work/bin:$PATH"
export CI_WORKFLOW_NAME=calico-1-pr-abcde CI_GIT_SHA=0123abc

# shellcheck source=batch-memo
source "$vms_dir/batch-memo"

write_plan() { # <scope> then "<group> <class> <key> <state>" lines on stdin
  mkdir -p "$STUB_WORKFLOW/felix-fv-plan"
  echo "$1" >"$STUB_WORKFLOW/felix-fv-plan/scope"
  cat >"$STUB_WORKFLOW/felix-fv-plan/lanes"
}

echo "== batch_memo_init"
rm -rf "$STUB_WORKFLOW/felix-fv-plan"
out="$work/out"
batch_memo_init 22.04-ipt >"$out"
check "no plan: memo off" [ -z "$BATCH_MEMO_PREFIX" ]
check "no plan: logged" grep -qE '^FV-MEMO-LANE lane=22.04-ipt outcome=off .*reason=no-plan' "$out"

write_plan felix-fv-memo/pr-1 <<'EOF'
22.04-ipt nonbpf k1 miss
bpf-24.04-ipt-with-ut bpf k2 hit
EOF
batch_memo_init 22.04-ipt >/dev/null
check "lane miss: prefix set" [ "$BATCH_MEMO_PREFIX" = felix-fv-memo/pr-1/k1 ]
check "lane miss: not a lane hit" [ "$BATCH_MEMO_LANE_HIT" = false ]
batch_memo_init bpf-24.04-ipt-with-ut >/dev/null
check "lane hit" [ "$BATCH_MEMO_LANE_HIT" = true ]
batch_memo_init 26.04-unknown >/dev/null
check "unknown lane: memo off" [ -z "$BATCH_MEMO_PREFIX" ]

write_plan "" <<'EOF'
22.04-ipt nonbpf k1 miss
EOF
batch_memo_init 22.04-ipt >/dev/null
check "no scope (not a PR): memo off" [ -z "$BATCH_MEMO_PREFIX" ]

echo "== skip, record, and restore"
export BATCH_MEMO_PREFIX=felix-fv-memo/pr-1/k1
run1="$work/run1/artifacts"
for b in ut 2; do
  mkdir -p "$run1/$b/report"
  echo "<testsuites/>" >"$run1/$b/report/felix_fv_$b.xml"
  batch_memo_record "$run1" "$b" >/dev/null
done

run2="$work/run2/artifacts"
batches=(ut 1 2 3)
batch_memo_skip_cached "$run2" >"$out"
check "cached batches are skipped" [ "${batches[*]}" = "1 3" ]
check "partial hit: logged" grep -qE '^FV-MEMO-LANE .* outcome=partial batches=4 cached=2 ran=2 ' "$out"
check "each skipped batch: logged" [ "$(grep -c '^FV-MEMO-BATCH .* cached-from=calico-1-pr-abcde@0123abc$' "$out")" = 2 ]
check "a skipped batch's report is restored" [ -f "$run2/2/report/felix_fv_2.xml" ]
check "a skipped batch says where it passed" grep -q "$CI_WORKFLOW_NAME" "$run2/ut/batch-memo-source"

batches=(4 5)
batch_memo_skip_cached "$run2" >"$out"
check "nothing cached: every batch runs" [ "${batches[*]}" = "4 5" ]
check "miss: logged" grep -qE '^FV-MEMO-LANE .* outcome=miss batches=2 cached=0 ran=2 ' "$out"

for b in 1 3; do
  mkdir -p "$run2/$b/report" && echo "<testsuites/>" >"$run2/$b/report/felix_fv_$b.xml"
done
batch_memo_record_lane "$run2" ut 1 2 3 >/dev/null
run3="$work/run3/artifacts"
batch_memo_restore_lane "$run3" >"$out"
check "lane hit: logged" grep -qE '^FV-MEMO-LANE .* outcome=lane batches=4 cached=4 ran=0 ' "$out"
for b in ut 1 2 3; do
  check "a lane hit restores batch $b" [ -f "$run3/$b/report/felix_fv_$b.xml" ]
done

echo
if [ "$fails" -ne 0 ]; then
  echo "$fails check(s) FAILED"
  exit 1
fi
echo "All checks passed"
