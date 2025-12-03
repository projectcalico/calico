# Common definitions for the tests that we run on VMs with a newer
# kernel than Semaphore itself provides.
set -e

num_fv_batches=${NUM_FV_BATCHES:-8}

if [[ ${RUN_UT} == "true" ]]; then
  export batches=(ut $(seq 1 ${num_fv_batches}))
else
  export batches=($(seq 1 ${num_fv_batches}))
fi

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
        ut-bpf
        check-wireguard
    )
  else # Numbered FV batch.
    cmd=(
        make
          --directory=${CALICO_DIR_NAME}/felix
          FELIX_FV_NFTABLES="$FELIX_FV_NFTABLES"
          FV_EXTRA_REPORT_SUFFIX="$FV_EXTRA_REPORT_SUFFIX"
          FELIX_FV_BPFATTACHTYPE="$FELIX_FV_BPFATTACHTYPE"
          GINKGO_FOCUS="${FV_FOCUS}"
          FV_NUM_BATCHES="$num_fv_batches"
          FV_BATCHES_TO_RUN="$batch"
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
  VM_NAME="$vm_name" ${remote_exec} "nohup bash -c '$cmd_quot > /tmp/test.log; echo \$? > /tmp/test.rc' < /dev/null >& /dev/null &"
  echo "RUNNER: Started batch '$batch' on VM '$vm_name', monitoring log..." >> "$log_file"

  # Subshell to limit scope of trap.
  (
    # Enable job control so that background processes get their own process groups.
    set -m

    # Monitor the log in the background with a retry loop.
    stopped=false
    while ! $stopped; do
      VM_NAME="$vm_name" ${remote_exec} 'tail -F -n 0 "/tmp/test.log" 2>/dev/null' >> "$log_file" || true
      echo "RUNNER: WARNING: Tail process on VM '$vm_name' ended, restarting..." >> "$log_file"
      sleep 1
    done &
    tail_pid=$!
    # Set a trap to stop the tail when we exit.  Note: negative PID means
    # "kill the process group", i.e. while loop and its children.
    trap 'stopped=true; kill -TERM -$tail_pid || true; wait $tail_pid || true' EXIT

    num_fails=0
    while true; do
      rc=$(VM_NAME="$vm_name" ${remote_exec} 'while [ ! -f /tmp/test.rc ]; do sleep 1; done; cat /tmp/test.rc' || echo "ssh error $?")
      # Verify that we got a number; if not, probably an ssh error or similar.
      if grep -q '^[0-9]\+$' <<< "$rc"; then
        echo "RUNNER: Batch '$batch' on VM '$vm_name' completed with rc=$rc" >> "$log_file"
        exit "$rc"
      else
        echo "RUNNER: Failed to read batch RC got '$rc', continuing to monitor log..." >> "$log_file"
        sleep 10
        num_fails=$((num_fails + 1))
        if [ "$num_fails" -ge 10 ]; then
          echo "RUNNER: Too many failures reading batch RC, aborting batch '$batch' on VM '$vm_name'" >> "$log_file"
          exit 1
        fi
      fi
    done
  )
}
