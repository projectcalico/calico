#!/usr/bin/env bash
# Smoke tests for run-and-monitor. Not run in CI; run manually in an
# environment with expect, stdbuf and script(1) available, e.g.:
#   docker run --rm -v $PWD:/w -w /w ubuntu:24.04 bash -c \
#     'apt-get update -qq && apt-get install -yqq expect bsdutils >/dev/null && .semaphore/test-run-and-monitor.sh'
set -x
cd "$(dirname "$0")/.."
fails=0

check() {
  local desc="$1"; shift
  if "$@"; then echo "PASS: $desc"; else echo "FAIL: $desc"; fails=$((fails+1)); fi
}

# 1. Success path: correct RC and final message.
out=$(script -qec "./.semaphore/run-and-monitor t1.log echo hello" /dev/null); rc=$?
check "success RC=0" [ "$rc" = 0 ]
check "success message" grep -q "SUCCEEDED" <<<"$out"
check "command output logged" grep -q hello artifacts/t1.log

# 2. Failure path: RC propagated.
script -qec "./.semaphore/run-and-monitor t2.log bash -c 'exit 3'" /dev/null; rc=$?
check "failure RC nonzero" [ "$rc" != 0 ]

# 3. Control characters in output are stripped from console (but kept in log);
#    >2000 lines so both the head and the output-tail paths run.
out=$(script -qec "./.semaphore/run-and-monitor t3.log bash -c 'for i in \$(seq 2500); do echo line\$i; done; printf \"SUCCESS junk:\\001\\002\\000here\\n\"'" /dev/null); rc=$?
check "ctrl-chars RC=0" [ "$rc" = 0 ]
check "no 0x01 on console" test -z "$(grep -aoP '\x01' <<<"$out")"
check "output-tail ran" grep -q "Tail of output" <<<"$out"
check "tail content sanitized" grep -q "junk:here" <<<"$out"
check "log keeps raw bytes" grep -qP '\x01' artifacts/t3.log

# 4. Terminal state restored: command disables ONLCR; final output must still
#    have CRLF endings (i.e. state restored before the final message).
out=$(script -qec "./.semaphore/run-and-monitor t4.log bash -c 'stty -onlcr < /dev/tty; echo done'" /dev/null); rc=$?
check "stty RC=0" [ "$rc" = 0 ]
check "final message has CRLF" grep -qP 'exit with RC=0\r$' <<<"$out"

echo "FAILURES: $fails"
exit $fails
