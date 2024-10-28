# Common definitions for the tests that we run on VMs with a newer
# kernel than Semaphore itself provides.

num_fv_batches=${NUM_FV_BATCHES:-8}

if [[ ${RUN_UT} == "true" ]]; then
  batches=(ut $(seq 1 ${num_fv_batches}))
else
  batches=($(seq 1 ${num_fv_batches}))
fi
