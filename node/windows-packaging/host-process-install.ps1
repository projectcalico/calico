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
$ErrorActionPreference = "Stop"
$rootDir = "c:\CalicoWindows"

Write-Host "Uninstalling any existing Calico install before proceeding with installation..."
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
if ($LastExitCode -NE 0) {
    exit $LastExitCode
}

# Restart kubelet and/or kube-proxy services if they are installed by Calico and
# running since their service files may have been updated in-place.
$kubeProxySvc = Get-CimInstance -Query 'select * from win32_service where name="kube-proxy"'
if ($kubeProxySvc.PathName.StartsWith($rootDir, 'CurrentCultureIgnoreCase')) {
    if ($kubeProxySvc.State -EQ "Running") {
        Write-Host "Restarting running kube-proxy service managed by Calico to reload service"
        Restart-Service kube-proxy
        $svc = Get-Service kube-proxy

        try {
            $svc.WaitForStatus("Running", "00:00:10")
        } catch {
            Write-Host "Error waiting for kube-proxy service to be Running"
            Write-Host $_
            exit $LastExitCode
        }

$kubeletSvc = Get-CimInstance -Query 'select * from win32_service where name="kubelet"'
if ($kubeletSvc.PathName.StartsWith($rootDir, 'CurrentCultureIgnoreCase')) {
    if ($kubeletSvc.State -EQ "Running") {
        Write-Host "Restarting running kubelet service managed by Calico to reload service"
        Restart-Service kubelet
        $svc = Get-Service kubelet

        try {
            $svc.WaitForStatus("Running", "00:00:10")
        } catch {
            Write-Host "Error waiting for kubelet service to be Running"
            Write-Host $_
            exit $LastExitCode
        }
    }
}
