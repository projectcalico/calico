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
# Configure docker.io registry mirror
sudo mkdir -p /etc/containerd/certs.d/docker.io
if [ ! -f /etc/containerd/certs.d/docker.io/hosts.toml ]; then
  sudo tee /etc/containerd/certs.d/docker.io/hosts.toml <<EOF
server = "https://registry-1.docker.io"

[host."https://mirror.gcr.io"]
  capabilities = ["pull", "resolve"]
EOF
else
  echo "The file /etc/containerd/certs.d/docker.io/hosts.toml already exists. Skipping..."
fi
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
  echo "Device $DEVICE_NODE does not exist. Please rerun the tool to try it again."
  exit 1
fi
# Set ext4 as the file system.
sudo mkfs.ext4 -F -m 0 -E lazy_itable_init=0,lazy_journal_init=0,discard $DEVICE_NODE
# Check if the filesystem was created successfully
if [ $? -ne 0 ]; then
  echo Failed to create the filesystem on $DEVICE_NODE. Please rerun the tool to try it again.
  exit 1
fi

# Install JQ
echo Installing JQ...
sudo apt-get --yes install jq

# Fetch and store the OAuth token of the service account in ACCESS_TOKEN.
echo Fetching OAuth token...
ACCESS_TOKEN=$(curl -sSf -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r '.access_token')

function remove_snapshot_views() {
  echo Removing the previously created snapshot views...
  views=($(sudo ctr -n k8s.io snapshot list | grep "View" | sed 's/ \{1,\}/,/g'))
  for row in "${views[@]}"; do
    view=$(echo "$row" | cut -d',' -f1)
    echo Removing the view $view
    sudo ctr -n k8s.io snapshot rm $view 2>/dev/null
  done
}

function pull_images() {
  echo Pulling the given container images...
  for param in "$@"; do
    echo Start pulling $param ...
    if [ "$OAUTH_MECHANISM" == "none" ]; then
      sudo ctr -n k8s.io image pull --hosts-dir "/etc/containerd/certs.d" "$param"
    elif [ "$OAUTH_MECHANISM" == "serviceaccounttoken" ]; then
      sudo ctr -n k8s.io image pull --hosts-dir "/etc/containerd/certs.d" --user "oauth2accesstoken:$ACCESS_TOKEN" "$param"
    else
      echo "Unknown OAuth mechanism, expected 'None' or 'ServiceAccountToken' but got '$OAUTH_MECHANISM'".
      exit 1
    fi
    if [ $? -ne 0 ]; then
      echo Failed to pull and unpack the image $param. Please rerun the tool to try it again.
      exit 1
    fi
  done
}

function write_image_info() {
  echo Writing image info to disk image...
  images=$(ctr -n k8s.io images ls)
  sudo echo "$images" >> "/mnt/disks/container_layers/images.metadata"
}

function process_snapshots() {
  echo Processing the snapshots...
  snapshots=($(sudo ctr -n k8s.io snapshot list | grep "Committed" | cut -d ' ' -f1))

  for snapshot in "${snapshots[@]}"; do
    echo Processing $snapshot

    # Add retry in case `ctr snapshot view` fails silently
    local retries=5
    while [ ${retries} -ge 1 ]; do
      ((retries--))
      sudo ctr -n k8s.io snapshot view tmp_$snapshot $snapshot
      # Check if the view was successfully created
      if [ $? -ne 0 ]; then
        echo "Failed to create snapshot view for $snapshot. Will retry. ${retries} retries left."
        continue
      fi

      original_path=$(sudo ctr -n k8s.io snapshot mount /tmp_$snapshot tmp_$snapshot | grep -oP '/\S+/snapshots/[0-9]+/fs' | tr ':' '\n' | head -n 1)
      if [[ -n "$original_path" ]]; then
        break
      fi
      echo "Failed to get mount point for tmp_$snapshot. Will retry. ${retries} retries left."
      echo "All snapshots:"
      sudo ctr -n k8s.io snapshot list
      sudo ctr -n k8s.io snapshot rm tmp_$snapshot
      sleep 1
    done

    if [[ -z "$original_path" ]]; then
      echo Failed to get snapshot directory for snapshot $snapshot. Please rerun the tool to try it again.
      exit 1
    fi

    new_path=$(echo $original_path | grep -o "snapshots/.*/fs")
    sudo mkdir -p "/mnt/disks/container_layers/${new_path}"
    sudo cp -r -p $original_path "/mnt/disks/container_layers/${new_path}/.."
    # Check if the data was successfully copied over to the new path
    if [ $? -ne 0 ]; then
      echo Failed to copy the snapshot files for $snapshot from $original_path to /mnt/disks/container_layers/${new_path}. Please rerun the tool to try it again.
      exit 1
    fi

    mapping="$snapshot $new_path"

    if [ "$STORE_SNAPSHOT_CHECKSUMS" = "true" ]; then
      echo "Calculating checksum for snapshot $snapshot"
      checksum="$(find /mnt/disks/container_layers/${new_path} -type f -exec md5sum {} + | cut -d' ' -f1 | LC_ALL=C sort | md5sum | cut -d' ' -f1)"
      mapping="$snapshot $new_path $checksum"
    fi

    echo "Appending $mapping to Metadata file"
    sudo echo "$mapping" >> "/mnt/disks/container_layers/snapshots.metadata"
    if [ $? -ne 0 ]; then
      echo Failed to write metadata view for $snapshot. Please rerun the tool to try it again.
      exit 1
    fi
  done
  echo Processing is done.
}

function unpack() {
  # Prepare the disk image directories.
  echo Preparing the disk image directories...
  sudo mkdir -p /mnt/disks/container_layers
  sudo mount -o discard,defaults $DEVICE_NODE /mnt/disks/container_layers
  # Check if the directory was successfully created
  if [ $? -ne 0 ]; then
    echo Failed to create the view for $snapshot. Please rerun the tool to try it again.
    exit 1
  fi
  sudo chmod a+w /mnt/disks/container_layers
  sudo rm /mnt/disks/container_layers/snapshots.metadata
  sudo touch /mnt/disks/container_layers/snapshots.metadata
  sudo chmod a+w /mnt/disks/container_layers/snapshots.metadata

  # Remove the previously created snapshot views.
  remove_snapshot_views

  # Store the first parameter in STORE_SNAPSHOT_CHECKSUMS and shift
  STORE_SNAPSHOT_CHECKSUMS=$(echo "$1")
  shift

  # Store the second parameter in OAUTH_MECHANISM and shift.
  OAUTH_MECHANISM=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  shift

  # Pull all the given images.
  pull_images "$@"

  # Write image info to disk image.
  write_image_info "$@"

  # Process the snapshots.
  process_snapshots

  # Remove the original pulled images.
  for img in "${@}"; do
    echo Removing the original pulled image $img ...
    sudo ctr -n k8s.io image rm "$img"
  done

  echo Content of snapshots.metadata file:
  sudo cat /mnt/disks/container_layers/snapshots.metadata

  # We want to unmount the directory, otherwise we don't be able to generate the
  # image properly.
  sudo umount /mnt/disks/container_layers

  # This script must print out this message as a signal to the caller script,
  # meaning the unpacking is completed and the disk image creation can begin.
  echo Unpacking is completed.
}
