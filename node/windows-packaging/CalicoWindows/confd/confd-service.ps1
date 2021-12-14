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

# This script is run from the main Calico directory.
. .\config.ps1

ipmo .\libs\calico\calico.psm1 -Force

# Autoconfigure the IPAM block mode.
if ($env:CNI_IPAM_TYPE -EQ "host-local") {
  $env:USE_POD_CIDR = "true"
} else {
  $env:USE_POD_CIDR = "false"
}

if($env:CALICO_NETWORKING_BACKEND = "windows-bgp")
{
  Wait-ForCalicoInit
  Write-Host "Windows BGP is enabled, running confd..."

  cd "$PSScriptRoot"

  # Remove the old peerings and blocks so that confd will always trigger
  # reconfiguration at start of day.  This ensures that stopping and starting the service
  # reliably recovers from previous failures.
  rm peerings.ps1 -ErrorAction SilentlyContinue
  rm blocks.ps1 -ErrorAction SilentlyContinue

  # Run the calico-confd binary.
  & ..\calico-node.exe -confd -confd-confdir="$PSScriptRoot"
} else {
  Write-Host "Windows BGP is disabled, not running confd."
  while($True) {
    Start-Sleep 10
  }
}

