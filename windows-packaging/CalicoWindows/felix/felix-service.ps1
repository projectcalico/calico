# Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script is run from the main Calico folder.
. .\config.ps1

ipmo .\libs\calico\calico.psm1 -Force

# Wait for vSwitch to be created, etc.
Wait-ForCalicoInit

# Copy the nodename from the global setting.
$env:FELIX_FELIXHOSTNAME = $env:NODENAME

# Disable OpenStack metadata server support, which is not available on Windows.
$env:FELIX_METADATAADDR = "none"

# VXLAN settings.
$env:FELIX_VXLANVNI = "$env:VXLAN_VNI"

# Autoconfigure the IPAM block mode.
if ($env:CNI_IPAM_TYPE -EQ "host-local") {
    $env:USE_POD_CIDR = "true"
} else {
    $env:USE_POD_CIDR = "false"
}

# Run the calico-felix binary.
.\calico-node.exe -felix
