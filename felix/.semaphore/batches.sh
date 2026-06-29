# Common definitions for the tests that we run on VMs with a newer
# kernel than Semaphore itself provides.
set -e

num_fv_batches=${NUM_FV_BATCHES:-8}

if [[ ${RUN_UT} == "true" ]]; then
  export batches=(ut $(seq 1 ${num_fv_batches}))
else
  export batches=($(seq 1 ${num_fv_batches}))
fi

# Determine pass/fail for a batch purely from its *streamed* log.  Used as a
# fallback when the VM stops responding before it can write test.rc -- e.g. a
# kernel BPF/vmap teardown deadlock that wedges the VM *after* the tests
# finished.  In that case test.rc never lands and ssh hangs, but the test
# framework's end-of-run summary line was already streamed to the runner host
# before the VM locked up, so we can still recover the verdict from it.
#
# Echoes "pass", "fail", or nothing (run not finished / no summary line yet).
# Anchored to each framework's end-of-run summary so a mid-run "PASS"/"SUCCESS"
# can never be mistaken for completion.
batch_log_verdict() {
  local batch="$1" log_file="$2"
  [ -f "$log_file" ] || return 0
  # Strip ANSI colour codes (ginkgo colourises its summary line).
  local tail_clean
  tail_clean="$(tail -n 300 "$log_file" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g')"
  if [ "$batch" = "ut" ]; then
    # gotestsum's final line:
    #   "DONE <n> tests[, <s> skipped][, <f> failures] in <d>s"
    local done_line
    done_line="$(grep -E '^DONE [0-9]+ tests' <<<"$tail_clean" | tail -n 1)"
    [ -z "$done_line" ] && return 0
    if grep -qE ', [0-9]+ (failures|errors)' <<<"$done_line"; then
      echo fail
    else
      echo pass
    fi
  else
    # ginkgo's final summary line: "SUCCESS! -- ..." or "FAIL! -- ...".
    if grep -qE '^FAIL!' <<<"$tail_clean"; then
      echo fail
    elif grep -qE '^SUCCESS!' <<<"$tail_clean"; then
      echo pass
    fi
  fi
  # Always succeed: callers do `verdict="$(batch_log_verdict ...)"` under
  # `set -e`, so a non-zero return (e.g. the no-match grep above) would abort
  # the batch.  The verdict is conveyed via stdout; "" means "not finished".
  return 0
}

# Capture the VM serial console (works via the GCP control plane even when ssh
# is dead) into an artifact next to the batch log, for diagnosing a wedged VM.
capture_serial_console() {
  local vm_name="$1" log_file="$2" batch="$3"
  local serial; serial="$(dirname "$log_file")/vm-serial-${batch}-wedged.log"
  echo "RUNNER: Capturing serial console for wedged VM '$vm_name' to $(basename "$serial")" >> "$log_file"
  timeout 120 gcloud compute instances get-serial-port-output "$vm_name" \
      --zone="${ZONE}" --port=1 > "$serial" 2>&1 \
      || echo "RUNNER: serial console capture failed/timed out" >> "$log_file"
}

# Write a synthetic JUnit report for a batch whose real report could not be
# retrieved because the VM wedged after the tests completed.  Mirrors the
# watchdog's synthetic report so the batch still appears in Semaphore test
# results (clearly labelled) instead of silently vanishing.
write_synthetic_report() {
  local batch="$1" log_file="$2" verdict="$3"
  local report_type batch_formatted
  if [ "$batch" = "ut" ]; then report_type="ut"; else report_type="fv"; fi
  if [[ "$batch" =~ ^[0-9]+$ ]]; then
    batch_formatted="$(printf '%03d' "$batch")"
  else
    batch_formatted="$batch"
  fi
  local report_dir; report_dir="$(dirname "$log_file")/$batch/report"
  mkdir -p "$report_dir"
  local failures=0 body=""
  if [ "$verdict" = fail ]; then
    failures=1
    body="<failure message=\"Batch ${batch} reported failure in its streamed log; the VM wedged before its real report could be retrieved.\"></failure>"
  fi
  cat > "$report_dir/felix_${report_type}_wedged_${batch_formatted}.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="batch-${batch}" tests="1" failures="${failures}" errors="0" time="0">
    <testcase name="batch ${batch} completion (VM wedged post-test)" classname="ci.wedge-recovery" time="0">${body}</testcase>
  </testsuite>
</testsuites>
EOF
}

run_batch() {
  local remote_exec="$1"
  local batch="$2"
  local vm_name="$3"
  local log_file="$4"
  local cmd=()
  if [ "$batch" = "ut" ]; then
    cmd=(
      make
        --directory=${CALICO_DIR_NAME}/felix
        FOCUS="${UT_FOCUS}"
        ut-bpf-no-prereqs
    )
  else # Numbered FV batch.
    cmd=(
        make
          --directory=${CALICO_DIR_NAME}/felix
          FELIX_FV_NFTABLES="$FELIX_FV_NFTABLES"
          FELIX_FV_NETKIT="$FELIX_FV_NETKIT"
          FV_EXTRA_REPORT_SUFFIX="$FV_EXTRA_REPORT_SUFFIX"
          FELIX_FV_BPFATTACHTYPE="$FELIX_FV_BPFATTACHTYPE"
          GINKGO_FOCUS="${FV_FOCUS}"
          FV_NUM_BATCHES="$num_fv_batches"
          FV_BATCHES_TO_RUN="$batch"
          check-wireguard
          "$FV_NO_PREREQ_TARGET"
    )
  fi
  
  local cmd_quot=""
  local first=true
  for part in "${cmd[@]}"; do
    if [ "$first" = true ]; then
      first=false
    else
      cmd_quot+=" "
    fi
    cmd_quot+="$(printf "%q" "$part")"
  done

  echo "RUNNER: Starting batch '$batch' on VM '$vm_name'" >> "$log_file"
  echo "RUNNER: Command: $cmd_quot" >> "$log_file"

  # We used to have occasional problems with ssh sessions dropping while tests
  # were running.  Avoid by running the tests in the background with nohup, and
  # monitoring the log file separately.
  #
  # Notes on nohup:
  # - We need to redirect stdin/stdout/stderr of the command to avoid holding
  #   open the ssh session.  Redirecting stdin is not strictly necessary here
  #   because the on-test-vm script already passes '-n' to ssh.
  # - Since the command will return immediately after putting the batch in the
  #   background, we need to monitor the log file separately. We do that with
  #   a retry loop.
  # - nohup swallows the return code of the process so we use a 'bash -c'
  #   wrapper to capture it in a file.
  # - We merge stderr into test.log (2>&1) so that any error emitted by make,
  #   docker, or the wrapped test command after the test binary exits (e.g.
  #   docker --rm cleanup hangs) is captured in the artifact rather than
  #   silently discarded by the outer '>& /dev/null'.
  VM_NAME="$vm_name" ${remote_exec} "nohup bash -c 'echo \$\$ > test.pid; $cmd_quot > test.log 2>&1; echo \$? > test.rc' < /dev/null >& /dev/null & while [ ! -e test.log ]; do sleep 1; done"
  echo "RUNNER: Started batch '$batch' on VM '$vm_name', monitoring log..." >> "$log_file"

  # Subshell to limit scope of trap.
  (
    # Enable job control so that background processes get their own process groups.
    set -m

    # Monitor the log in the background with a retry loop.
    stopped=false
    while ! $stopped; do
      VM_NAME="$vm_name" ${remote_exec} 'tail -F -n 0 "test.log" 2>/dev/null' >> "$log_file" || true
      echo "RUNNER: WARNING: Tail process on VM '$vm_name' ended, restarting..." >> "$log_file"
      sleep 1
    done &
    tail_pid=$!
    # Set a trap to stop the tail when we exit.  Note: negative PID means
    # "kill the process group", i.e. while loop and its children.
    trap 'stopped=true; kill -TERM -$tail_pid || true; wait $tail_pid || true' EXIT

    # Poll the VM for the batch's exit code.  wait-for-test-completion is
    # single-shot (returns "running" / a number / "66"); we own the cadence and
    # the timeout here.  Each poll is bounded by 'timeout' so a wedged VM -- one
    # where even a trivial ssh never returns -- cannot block this loop.  That is
    # the case that matters: when a batch wedges the VM *after* its tests
    # finished (kernel BPF/vmap teardown deadlock), test.rc never lands and ssh
    # hangs, but the framework's end-of-run summary was already streamed to us,
    # so we recover the verdict from the log rather than waiting for the
    # 55-minute watchdog.
    unresponsive=0
    while true; do
      status="$(timeout 30 env VM_NAME="$vm_name" ${remote_exec} \
                  "$CALICO_DIR_NAME/felix/.semaphore/wait-for-test-completion" 2>/dev/null)" \
        || status=""

      if [ "$status" = "running" ]; then
        unresponsive=0
        sleep 10
        continue
      fi

      if [ "$status" = "66" ]; then
        echo "RUNNER: WARNING: Batch '$batch' on VM '$vm_name' stopped without outputting its RC file (possible VM crash/reboot?)." >> "$log_file"
        capture_serial_console "$vm_name" "$log_file" "$batch"
        echo "RUNNER: Batch '$batch' on VM '$vm_name' completed with rc=66" >> "$log_file"
        exit 66
      fi

      if [[ "$status" =~ ^[0-9]+$ ]]; then
        echo "RUNNER: Batch '$batch' on VM '$vm_name' completed with rc=$status" >> "$log_file"
        exit "$status"
      fi

      # Empty/non-numeric: the ssh poll failed or timed out -- the VM is not
      # responding.  Before treating that as an infra failure, check whether the
      # streamed log already shows the batch finished (the post-test wedge case).
      verdict="$(batch_log_verdict "$batch" "$log_file")"
      if [ -n "$verdict" ]; then
        capture_serial_console "$vm_name" "$log_file" "$batch"
        write_synthetic_report "$batch" "$log_file" "$verdict"
        local rc=1
        [ "$verdict" = "pass" ] && rc=0
        echo "RUNNER: VM '$vm_name' is unresponsive, but the streamed log shows batch '$batch' finished ($verdict). The VM most likely wedged during post-test teardown (kernel BPF/vmap deadlock -- see vm-serial-${batch}-wedged.log). Recording rc=$rc from the streamed log." >> "$log_file"
        exit "$rc"
      fi

      unresponsive=$((unresponsive + 1))
      echo "RUNNER: Batch '$batch' on VM '$vm_name': ssh poll failed and no end-of-run marker in the log yet (attempt $unresponsive); continuing to monitor..." >> "$log_file"
      if [ "$unresponsive" -ge 10 ]; then
        echo "RUNNER: VM '$vm_name' has been unresponsive too long with no completion marker; aborting batch '$batch'." >> "$log_file"
        capture_serial_console "$vm_name" "$log_file" "$batch"
        exit 1
      fi
      sleep 15
    done
  )
}
