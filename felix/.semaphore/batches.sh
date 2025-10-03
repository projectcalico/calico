# Common definitions for the tests that we run on VMs with a newer
# kernel than Semaphore itself provides.
set +e
num_fv_batches=${NUM_FV_BATCHES:-8}

if [[ ${RUN_UT} == "true" ]]; then
  batches=(ut $(seq 1 ${num_fv_batches}))
else
  batches=($(seq 1 ${num_fv_batches}))
fi

run_batch() {
  local remote_exec="$1"
  local batch="$2"
  local vm_name="$3"
  local log_file="$4"

  if [ "$batch" = "ut" ]; then
    VM_NAME="$vm_name" ${remote_exec} make --directory=calico/${REPO_NAME} FOCUS="${UT_FOCUS}" ut-bpf check-wireguard >& "$log_file"
  else
    VM_NAME="$vm_name" ${remote_exec} make --directory=calico/${REPO_NAME} fv-bpf FELIX_FV_NFTABLES="$FELIX_FV_NFTABLES" FELIX_FV_BPFATTACHTYPE="$FELIX_FV_BPFATTACHTYPE" GINKGO_FOCUS="${FV_FOCUS}" FV_NUM_BATCHES="$num_fv_batches" FV_BATCHES_TO_RUN="$batch" >& "$log_file"
  fi
}
