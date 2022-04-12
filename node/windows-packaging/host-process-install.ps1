# Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

# This script is the entrypoint for the install container for the HostProcess
# container installation.
# - If Calico for Windows services are running, run the uninstall.
Write-Host "Uninstalling any existing Calico install before proceeding with installation..."

$rootDir = "c:\CalicoWindows"
$calicoSvcsRunning = (Get-Service | where Name -Like 'Calico*') -NE $null
if ((Get-Service | where Name -Like 'Calico*') -NE $null) {
    Write-Host "Calico services running. Executing $rootDir\uninstall-calico.ps1..."
    & "$rootDir\uninstall-calico.ps1"
}
# If this is a hostprocess install, and the root install dir exists, try
# removing any Calico CNI config install
elseif (Test-Path $RootDir) {
    # Load existing config and check if Calico CNI was configured.
	if ((Test-Path "$rootDir\config.ps1") -and $env:CALICO_NETWORKING_BACKEND -NE "none") {
        . $RootDir\config.ps1
        Write-Host "Root dir $rootDir exists. Removing Calico CNI plugin if installed..."
        Remove-CNIPlugin
    }
} else {
    Write-Host "No Calico services found."
}
# Finally, start the install script.
& ".\install-calico-windows.ps1" -StartCalico no
exit $LastExitCode

