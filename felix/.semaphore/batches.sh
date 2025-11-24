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
  
  echo "Starting batch '$batch' on VM '$vm_name'" | tee "$log_file"
  echo "Command: $cmd_quot" | tee -a "$log_file"
  
  VM_NAME="$vm_name" ${remote_exec} "nohup bash -c \"$cmd_quot; echo \$? > /tmp/test-rc\"" 2>&1 >> "$log_file" < /dev/null
  echo "Started batch '$batch' on VM '$vm_name', monitoring log..." | tee -a "$log_file"
  while true; do
    VM_NAME="$vm_name" ${remote_exec} 'tail -F -n 0 "nohup.out" 2>/dev/null' >> "$log_file" < /dev/null || true
    echo "Tail process on VM '$vm_name' ended (rc=${PIPESTATUS[0]}), restarting..." | tee -a "$log_file"
    sleep 1
  done &
  local tail_pid=$!
  while true; do
    local rc
    rc=$(VM_NAME="$vm_name" ${remote_exec} 'while [ ! -f /tmp/test-rc ]; do sleep 1; done; cat /tmp/test-rc' < /dev/null)
    # Verify that we got a number; if not, probably an ssh error or similar.
    if grep -q '^[0-9]\+$' <<< "$rc"; then
      echo "Batch '$batch' on VM '$vm_name' completed with rc=$rc" | tee -a "$log_file"
      kill "$tail_pid" || true
      wait "$tail_pid" || true
      return "$rc"
    else
      echo "Failed to read batch RC got '$rc', continuing to monitor log..." | tee -a "$log_file"
    fi
  done
}
