# Common definitions for the tests that we run on VMs with a newer
# kernel than Semaphore itself provides.

num_fv_batches=${NUM_FV_BATCHES:-8}
batches=(ut $(seq 1 ${num_fv_batches}))
