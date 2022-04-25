# Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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
param
(
    [bool][parameter(Mandatory=$false)]$ExceptUpgradeService = $false
)

ipmo "$PSScriptRoot\libs\calico\calico.psm1" -Force

. $PSScriptRoot\config.ps1

Test-CalicoConfiguration

$ErrorActionPreference = 'SilentlyContinue'

# If running in a hostprocess container, remove Calico CNI if installed.
# Skip the rest of the logic that applies to manual installations only.
if (($env:CONTAINER_SANDBOX_MOUNT_POINT) -and ($env:CALICO_NETWORKING_BACKEND -NE "none"))
{
    if ($env:CALICO_NETWORKING_BACKEND -NE "none") {
        Remove-CNIPlugin
    }
    exit $lastexitcode
}

Write-Host "Stopping Calico if it is running..."
& $PSScriptRoot\stop-calico.ps1 -ExceptUpgradeService $ExceptUpgradeService

if ($env:CALICO_NETWORKING_BACKEND -EQ "windows-bgp")
{
    Remove-ConfdService
}

if ($env:CALICO_NETWORKING_BACKEND -NE "none")
{
    Remove-CNIPlugin
}

Remove-NodeService
Remove-FelixService

if (-Not $ExceptUpgradeService) {
    Remove-UpgradeService
}

Get-Module 'calico' | Remove-Module -Force
Write-Host "Done."
