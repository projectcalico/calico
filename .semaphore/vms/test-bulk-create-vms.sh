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

# Smoke tests for bulk-create-vms' machine-type fallback and retry.
# Not run in CI; run manually:
#   .semaphore/vms/test-bulk-create-vms.sh
#
# gcloud and sleep are stubbed on PATH.  Each test lists, per machine type, the
# outcome of successive create attempts; the stub replays them, as an immediate
# rejection or as a bulk-insert operation that the poll then reads back.
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

# Outcomes: ok, slow-ok (RUNNING on the first poll), stockout, quota and
# internal (in the operation), quota-sync and capacity-sync (rejected up front),
# invalid (a non-retryable operation error), mincount (the summary code alone)
# and reject (a non-retryable up-front rejection).  Operation failures carry VM_MIN_COUNT_NOT_REACHED beside their
# cause, as GCE reports them.
cat >"$stub_dir/gcloud" <<'STUB'
#!/usr/bin/env bash
state="$STUB_STATE"
arg() { local a; for a in "${@:2}"; do [[ "$a" == "--$1="* ]] && echo "${a#*=}"; done; }
case "$*" in
  *"instances bulk create"*)
    type=$(arg machine-type "$@")
    echo "create $type" >>"$state/calls"
    echo "$type $(arg boot-disk-type "$@")" >>"$state/disks"
    n=$(( $(cat "$state/n-$type" 2>/dev/null || echo 0) + 1 ))
    echo "$n" >"$state/n-$type"
    outcome=$(grep "^$type " "$state/outcomes" | cut -d' ' -f2 | tr ',' '\n' | sed -n "${n}p")
    case "$outcome" in
      quota-sync)
        printf "ERROR: (gcloud.compute.instances.bulk.create) Could not fetch resource:\n - Quota 'C4D_CPUS' exceeded.  Limit: 24.0 in region us-central1.\n" >&2
        exit 1 ;;
      capacity-sync)
        printf '%s\n' "ERROR: (gcloud.compute.instances.bulk.create) HttpError accessing <https://compute.googleapis.com/compute/v1/projects/p/regions/us-central1/instances/bulkInsert?alt=json>: response: <{'status': '503'}>, content <{" \
          '  "error": {' '    "code": 503,' \
          '    "message": "Region does not currently have sufficient capacity for the requested resources.",' \
          '    "errors": [{"message": "Region does not currently have sufficient capacity for the requested resources.", "domain": "global", "reason": "insufficientCapacity"}]' \
          '  }' '}' >&2
        exit 1 ;;
      reject)
        printf "ERROR: (gcloud.compute.instances.bulk.create) Invalid value for field 'resource.machineType'\n" >&2
        exit 1 ;;
    esac
    echo "$outcome" >"$state/group-$type-$n"
    echo "$type-$n"
    ;;
  *"operations list"*)
    group=$(arg filter "$@"); group="${group#operationGroupId=}"
    outcome=$(cat "$state/group-$group")
    if [ "$outcome" = slow-ok -a ! -e "$state/polled-$group" ]; then
      touch "$state/polled-$group"
      echo '[{"status": "RUNNING"}]'
      exit 0
    fi
    case "$outcome" in
      ok|slow-ok) echo '[{"status": "DONE"}]' ;;
      stockout) codes="VM_MIN_COUNT_NOT_REACHED ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS" ;;
      quota) codes=QUOTA_EXCEEDED ;;
      internal) codes="VM_MIN_COUNT_NOT_REACHED INTERNAL_ERROR" ;;
      invalid) codes="VM_MIN_COUNT_NOT_REACHED INVALID_FIELD_VALUE" ;;
      mincount) codes=VM_MIN_COUNT_NOT_REACHED ;;
      *) echo "stub: no outcome for group $group" >&2; exit 1 ;;
    esac
    if [ -n "${codes:-}" ]; then
      errs=$(printf '{"code": "%s"},' $codes)
      printf '[{"status": "DONE", "error": {"errors": [%s]}}]\n' "${errs%,}"
    fi
    ;;
  *) echo "stub gcloud: unexpected call: $*" >&2; exit 1 ;;
esac
STUB

cat >"$stub_dir/sleep" <<'STUB'
#!/usr/bin/env bash
echo "sleep $1" >>"$STUB_STATE/calls"
STUB

chmod +x "$stub_dir"/*
export PATH="$stub_dir:$PATH"

# shellcheck source=bulk-create-vms
source ./bulk-create-vms

export VM_MACHINE_TYPES="c4d n4d c3 n4"

# run <retry minutes> <"type outcome,outcome..." lines...>
run() {
  export VM_CREATE_RETRY_MINUTES="$1"
  shift
  export STUB_STATE="$work/state-$RANDOM$RANDOM"
  mkdir -p "$STUB_STATE"
  printf '%s\n' "$@" >"$STUB_STATE/outcomes"
  : >"$STUB_STATE/calls"
  vm_machine_type="" vm_create_summary=""
  bulk_create_vms "vm-1,vm-2" us-central1 --labels=x >"$STUB_STATE/out" 2>&1
  rc=$?
}

calls() { tr '\n' ' ' <"$STUB_STATE/calls" | sed 's/ $//'; }
output_has() { grep -qF -- "$1" "$STUB_STATE/out"; }

run 15 "c4d ok"
check "first type with capacity is used" [ "$rc" = 0 -a "$vm_machine_type" = c4d ]
check "only one create call" [ "$(calls)" = "create c4d" ]
check "start banner names the type" output_has "===== Test VMs: 2 × c4d in us-central1 (attempt 1"

run 15 "c4d stockout" "n4d ok"
check "stockout falls back to the next type" [ "$rc" = 0 -a "$vm_machine_type" = n4d ]
check "no sleep within a pass" [ "$(calls)" = "create c4d create n4d" ]
check "summary records the earlier stockout" \
  grep -qF "earlier failures: c4d: VM_MIN_COUNT_NOT_REACHED ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS" <<<"$vm_create_summary"

run 15 "c4d quota" "n4d quota-sync" "c3 ok"
check "both kinds of quota error fall back" [ "$rc" = 0 -a "$vm_machine_type" = c3 ]

run 15 "c4d capacity-sync" "n4d ok"
check "a region short of a family up front falls back" [ "$rc" = 0 -a "$vm_machine_type" = n4d ]
check "the up-front shortage is named" \
  grep -qF "earlier failures: c4d: REGION_INSUFFICIENT_CAPACITY" <<<"$vm_create_summary"

run 15 "c4d internal" "n4d ok"
check "a GCE internal error falls back" [ "$rc" = 0 -a "$vm_machine_type" = n4d ]

run 15 "c4d slow-ok"
check "polls until the operation is done" [ "$rc" = 0 -a "$(calls)" = "create c4d sleep 10" ]

run 15 "c4d invalid" "n4d ok"
check "non-retryable operation error fails at once" [ "$rc" = 1 -a "$(calls)" = "create c4d" ]
check "failure banner names the error" output_has "non-retryable error (VM_MIN_COUNT_NOT_REACHED INVALID_FIELD_VALUE)"

run 15 "c4d mincount" "n4d ok"
check "the summary code without a cause fails at once" [ "$rc" = 1 -a "$(calls)" = "create c4d" ]

run 15 "c4d reject" "n4d ok"
check "non-quota rejection fails at once" [ "$rc" = 1 -a "$(calls)" = "create c4d" ]

run 15 "c4d stockout,ok" "n4d stockout" "c3 quota" "n4 stockout"
check "after a failed pass, backs off and restarts from the top" \
  [ "$rc" = 0 -a "$vm_machine_type" = c4d ]
check "one backoff between the passes" \
  grep -qE "^create c4d create n4d create c3 create n4 sleep (6|7|8)[0-9] create c4d$" <<<"$(calls)"

VM_MACHINE_TYPES="t2d-standard-4 z3-highmem-8 c4d-standard-4" run 15 "t2d-standard-4 stockout" "z3-highmem-8 stockout" "c4d-standard-4 ok"
check "boot disk follows the family, Hyperdisk unless known older" \
  [ "$(tr '\n' ' ' <"$STUB_STATE/disks")" = "t2d-standard-4 pd-balanced z3-highmem-8 hyperdisk-balanced c4d-standard-4 hyperdisk-balanced " ]
check "the chosen disk is reported for replacements" [ "$vm_boot_disk_type" = hyperdisk-balanced ]

run 0 "c4d stockout" "n4d stockout" "c3 stockout" "n4 stockout"
check "gives up at the deadline mid-pass" [ "$rc" = 1 -a "$(calls)" = "create c4d" ]
check "failure banner reports the attempts" output_has "no capacity or quota after 1 attempts"

run 1 "c4d stockout" "n4d stockout" "c3 stockout" "n4 stockout"
check "no backoff that would end past the deadline" \
  [ "$rc" = 1 -a "$(calls)" = "create c4d create n4d create c3 create n4" ]

if [ "$fails" -gt 0 ]; then
  echo "$fails check(s) FAILED"
  exit 1
fi
echo "All checks passed"
