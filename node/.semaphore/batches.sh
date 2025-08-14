# Common definitions for the tests that are run on cloud
# VMs rather than Semaphore VMs

batches=(k8s-test)

run_batch() {
  local remote_exec="$1"
  local batch="$2"
  local vm_name="$3"
  local log_file="$4"
  local pid

  case $batch in
    k8s-test)
      cmd="make --directory=calico/${REPO_NAME} k8s-test"
      ;;
    *)
      echo "invalid batch name" && exit 1
      ;;
  esac

  VM_NAME="$vm_name" ${remote_exec} $cmd >& "$log_file"
}
