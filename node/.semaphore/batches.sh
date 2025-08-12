# Common definitions for the tests that are run on cloud
# VMs rather than Semaphore VMs

batches=(k8s-test)

run_batch() {
  local batch="$1"
  local vm_name="$2"
  local log_file="$3"
  local pid
 
  case $batch in
    k8s-test)
      cmd="make --directory=calico/${REPO_NAME} k8s-test"
      ;;
    *)
      echo "invalid batch name" && exit 1
      ;;
  esac

  ../.semaphore/vms/on-test-vm ${vm_name} $cmd >& "$log_file" &
  pid=$!

  echo "$pid"
}
