#!/usr/bin/env bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Smoke tests for spot-vms.  Not run in CI; run manually:
#   .semaphore/vms/test-spot-vms.sh
#
# gcloud, curl and sleep are stubbed on PATH; each test writes the stubs'
# answers into $STUB_STATE.
set -u
cd "$(dirname "$0")" || exit 1
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
mkdir -p "$stub_dir"

# ops-<n>: what the nth operations list prints, or "fail".  status: what
# describe prints, "gone" for a deleted VM, "gone-after-<n>" to delete it on the
# nth call.  create-<type>: ok or fail.
cat >"$stub_dir/gcloud" <<'STUB'
#!/usr/bin/env bash
state="$STUB_STATE"
echo "$*" >>"$state/calls"
next() { local n=$(( $(cat "$state/n-$1" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$state/n-$1"; echo "$n"; }
case "$*" in
  *"operations list"*)
    f="$state/ops-$(next ops)"
    [ -f "$f" ] || f="$state/ops-default"
    [ "$(cat "$f" 2>/dev/null)" != fail ] || exit 1
    cat "$f" 2>/dev/null
    ;;
  *"instances describe"*)
    n=$(next describe)
    s=$(cat "$state/status")
    if [ "$s" = gone ] || { [[ "$s" == gone-after-* ]] && [ "$n" -ge "${s#gone-after-}" ]; }; then
      echo "ERROR: (gcloud.compute.instances.describe) Could not fetch resource: - The resource 'projects/p/zones/z/instances/vm' was not found" >&2
      exit 1
    fi
    [[ "$s" != gone-after-* ]] || s=STOPPING
    echo "$s"
    ;;
  *"instances create"*)
    for a in "$@"; do [[ "$a" != --machine-type=* ]] || type="${a#*=}"; done
    echo "create $type" >>"$state/creates"
    [ "$(cat "$state/create-$type" 2>/dev/null)" = ok ]
    ;;
  *"auth print-access-token"*) echo token ;;
  *"config get-value project"*) echo proj ;;
  *"zones list"*) printf 'us-central1-a\nus-central1-b\n' ;;
  *) echo "stub gcloud: unexpected call: $*" >&2; exit 1 ;;
esac
STUB

cat >"$stub_dir/curl" <<'STUB'
#!/usr/bin/env bash
body="${*: -1}"
type=$(sed 's/.*"machineTypes":\["\([^"]*\)".*/\1/' <<<"$body")
zone=$(sed 's/.*"zone":"zones\/\([^"]*\)".*/\1/' <<<"$body")
cat "$STUB_STATE/advice-$type-$zone" 2>/dev/null || { echo "curl: (28) timed out" >&2; exit 28; }
STUB

cat >"$stub_dir/sleep" <<'STUB'
#!/usr/bin/env bash
echo "sleep $1" >>"$STUB_STATE/calls"
STUB

chmod +x "$stub_dir"/*
export PATH="$stub_dir:$PATH"

# shellcheck source=bulk-create-vms
source ./bulk-create-vms
# shellcheck source=spot-vms
source ./spot-vms

fresh() {
  export STUB_STATE="$work/state-$RANDOM$RANDOM"
  mkdir -p "$STUB_STATE"
  : >"$STUB_STATE/calls"
  echo RUNNING >"$STUB_STATE/status"
}

now=$(date +%s)
created=$((now - 3600))
recent="$(date -d "@$((now - 30))" --iso-8601=seconds)"
before="$(date -d "@$((created - 60))" --iso-8601=seconds)"

# Preemption check.  A failure 200s ago is past both polling limits, so these
# answer from a single look.
fresh
echo "$recent" >"$STUB_STATE/ops-default"
at=$(vm_preemption_check vm z "$created" $((now - 200)))
check "a preemption after creation is found" [ $? = 0 -a "$at" = "$recent" ]

fresh
echo "$before" >"$STUB_STATE/ops-default"
vm_preemption_check vm z "$created" $((now - 200)) >/dev/null
check "a preemption of an earlier same-named VM is ignored" [ $? = 1 ]

fresh
: >"$STUB_STATE/ops-default"
vm_preemption_check vm z "$created" $((now - 200)) >/dev/null
check "no preemption, VM still RUNNING: not preempted" [ $? = 1 ]
check "  without waiting" [ "$(grep -c sleep "$STUB_STATE/calls")" = 0 ]

fresh
echo fail >"$STUB_STATE/ops-default"
vm_preemption_check vm z "$created" $((now - 200)) >/dev/null
check "GCE can't be asked: check failed" [ $? = 2 ]

fresh
: >"$STUB_STATE/ops-1"
echo "$recent" >"$STUB_STATE/ops-2"
at=$(vm_preemption_check vm z "$created" "$now")
check "a preemption recorded after the failure is found by polling" [ $? = 0 -a "$at" = "$recent" ]
check "  without asking about RUNNING inside 60s" [ "$(grep -c 'instances describe' "$STUB_STATE/calls")" = 0 ]

fresh
: >"$STUB_STATE/ops-default"
echo RUNNING >"$STUB_STATE/status"
vm_preemption_check vm z "$created" $((now - 61)) >/dev/null
check "RUNNING 60s after the failure ends the check early" [ $? = 1 -a "$(grep -c sleep "$STUB_STATE/calls")" = 0 ]

# Waiting for the preempted VM to go.
fresh
echo gone-after-3 >"$STUB_STATE/status"
vm_wait_gone vm z 300
check "waits until the VM is gone" [ $? = 0 -a "$(cat "$STUB_STATE/n-describe")" = 3 ]

fresh
echo STOPPING >"$STUB_STATE/status"
vm_wait_gone vm z 0
check "gives up at the deadline" [ $? = 1 ]

# On-demand replacement.
export VM_MACHINE_TYPES="c4d n4d c3"
fresh
echo ok >"$STUB_STATE/create-c3d"
type=$(create_on_demand_replacement vm z c3d --labels=ci-provisioning=standard 2>/dev/null)
check "the preempted type is tried first" [ $? = 0 -a "$type" = c3d ]
check "  with the caller's labels" grep -q -- "--labels=ci-provisioning=standard" "$STUB_STATE/calls"
check "  with no provisioning model" bash -c "! grep -q -- --provisioning-model '$STUB_STATE/calls'"

fresh
echo ok >"$STUB_STATE/create-c3"
type=$(create_on_demand_replacement vm z n4d 2>/dev/null)
check "then the rest of VM_MACHINE_TYPES, once each" \
  [ $? = 0 -a "$type" = c3 -a "$(tr '\n' ' ' <"$STUB_STATE/creates")" = "create n4d create c4d create c3 " ]

fresh
create_on_demand_replacement vm z c4d >/dev/null 2>&1
check "no capacity anywhere fails" [ $? = 1 -a "$(wc -l <"$STUB_STATE/creates")" = 3 ]

# Capacity scores.
fresh
echo '{"recommendations":[{"scores":{"obtainability":0.9,"estimatedUptime":"3600s"}}]}' >"$STUB_STATE/advice-c3d-us-central1-a"
echo '{"recommendations":[{"scores":{"obtainability":0.5,"estimatedUptime":"60s"}}]}' >"$STUB_STATE/advice-c3d-us-central1-b"
scores="$STUB_STATE/scores"
out=$(record_capacity_scores us-central1 16 "$scores" c3d c4d 2>"$STUB_STATE/err")
check "always succeeds" [ $? = 0 ]
check "one FV-CAPACITY line per type and zone" [ "$(grep -c '^FV-CAPACITY ' <<<"$out")" = 4 ]
check "  carrying the score" \
  grep -qE "^FV-CAPACITY run=.* type=c3d zone=us-central1-a count=16 obtainability=0.9 uptime=3600s$" <<<"$out"
check "a failed call is recorded as an error" \
  grep -qE "type=c4d zone=us-central1-b count=16 obtainability=error uptime=error$" <<<"$out"
check "  and logged as one" grep -q "^error: capacity advisor gave no score for c4d" "$STUB_STATE/err"
check "labels carry the VM's own score, without dots" \
  [ "$(capacity_labels "$scores" c3d us-central1-b)" = "ci-cap-obtainability=0-5,ci-cap-uptime=60s" ]
check "no label without a score" [ -z "$(capacity_labels "$scores" n4 us-central1-b)" ]

if [ "$fails" -gt 0 ]; then
  echo "$fails check(s) FAILED"
  exit 1
fi
echo "All checks passed"
