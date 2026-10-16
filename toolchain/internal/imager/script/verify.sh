#  Copyright 2023 Google LLC
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

sudo apt update
sudo apt-get update

# Install containerd.
sudo apt install --yes containerd
# Start containerd.
sudo systemctl start containerd
# Check to see if containerd is up and we can use ctr.
if sudo ctr version | grep "Server:"; then
  echo containerd is ready to use
else
  echo containerd is not running. Please rerun the tool to try it again.
  exit 1
fi

# Check if disk is partitioned and update device node file path accordingly if so.
# The device name that maps to the `google-<device_name>` path is defined here: https://github.com/GoogleCloudPlatform/ai-on-gke/blob/4b73f02abd71e3c2a836d4d0ce29de054a605bc6/gke-disk-image-builder/imager.go#L32
# The disk name prefix is constructed here: https://github.com/GoogleCloudPlatform/ai-on-gke/blob/4b73f02abd71e3c2a836d4d0ce29de054a605bc6/gke-disk-image-builder/imager.go#L115
DEVICE_NODE=/dev/disk/by-id/google-secondary-disk-image-disk
if [[ -e "$DEVICE_NODE-part1" ]]; then
  DEVICE_NODE="$DEVICE_NODE-part1"
fi
echo "using device node: $DEVICE_NODE"

# Check if the device exists
if ! [ -b "$DEVICE_NODE" ]; then
  echo "Image verfication failure: failed to get device: Device $DEVICE_NODE does not exist. Please rerun the tool to try it again."
  exit 1
fi

function verify_snapshots() {
  # Prepare the disk image directories.
  echo Preparing the disk image directories...
  sudo mkdir -p /mnt/disks/container_layers
  sudo mount -o discard,defaults $DEVICE_NODE /mnt/disks/container_layers

  echo verifying the snapshots...
  sudo ls /mnt/disks/container_layers
  snapshot_metadata_file="/mnt/disks/container_layers/snapshots.metadata"
  while IFS= read -r line
  do
    echo "$line"
    snapshot_chainID=$(echo $line | cut -d' ' -f1)
    snapshot_path=$(echo $line | cut -d' ' -f2)
    expected_checksum=$(echo $line | cut -d' ' -f3)
    
    if [ -z "$expected_checksum" ]; then
      echo "Image verfication failure: Expected checksums not found in snapshots.metadata. Please use --store-snapshot-checksum flag when building images."
      exit 1
    fi

    actual_checksum="$(find /mnt/disks/container_layers/${snapshot_path} -type f -exec md5sum {} + | cut -d' ' -f1 | LC_ALL=C sort | md5sum | cut -d' ' -f1)"

    if [ "$expected_checksum" = "$actual_checksum" ]; then
      echo "Verification succeeds for snapshot $snapshot_chainID at $snapshot_path."
    else
      echo "Verification fails for snapshot $snapshot_chainID at $snapshot_path. Expected checksum: $expected_checksum, got: $actual_checksum"
      snapshot_broken="true"
    fi
  done < "$snapshot_metadata_file"

  if [ -n "$snapshot_broken" ]; then
    echo "Image verfication failure: Snapshot checksum mismatch. Please see the log to find more details."
  else
    echo "Disk image verification succeeds."
  fi
}
