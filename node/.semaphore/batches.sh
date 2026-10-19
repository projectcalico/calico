# Common definitions for the tests that are run on cloud
# VMs rather than Semaphore VMs
set -e

export batches=(k8s-test)

run_batch() {
  local remote_exec="$1"
  local batch="$2"
  local vm_name="$3"
  local log_file="$4"

  case $batch in
    k8s-test)
      cmd=("make" "--directory=${CALICO_DIR_NAME}/node" "k8s-test")
      ;;
    *)
      echo "invalid batch name" && exit 1
      ;;
  esac

  # A run that built toolchain images names them in CI_TOOLCHAIN_ENV, as NAME=image
  # lines make takes as overrides; the VM must build and test with the same ones.
  if [ -n "${CI_TOOLCHAIN_ENV:-}" ]; then
    while IFS= read -r kv; do
      [ -n "$kv" ] && cmd+=("$kv")
    done <<< "${CI_TOOLCHAIN_ENV}"
  fi
  VM_NAME="$vm_name" ${remote_exec} "${cmd[@]}" >& "$log_file"
}
