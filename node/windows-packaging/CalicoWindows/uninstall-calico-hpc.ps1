# Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

<#
.DESCRIPTION
    This script stops Calico services and fully uninstalls Calico on a Windows node.
#>

Param(
    [parameter(Mandatory = $false)] $NSSMPath="$env:CONTAINER_SANDBOX_MOUNT_POINT/nssm.exe"
)

$ErrorActionPreference = 'SilentlyContinue'

function Remove-CalicoService($ServiceName)
{
    $svc = Get-Service | where Name -EQ "$ServiceName"
    if ($svc -NE $null)
    {
        if ($svc.Status -EQ 'Running')
        {
            Write-Host "$ServiceName service is running, stopping it..."
            & $NSSMPath stop $ServiceName confirm
        }
        Write-Host "Removing $ServiceName service..."
        & $NSSMPath remove $ServiceName confirm
    }
}

# Only clean up CNI dirs if using Calico CNI
if ("$env:CNI_PLUGIN_TYPE" -eq "Calico") {
    if ("$env:CNI_NET_DIR" -eq $null)
    {
        Write-Host "CNI_NET_DIR env var not set, skipping Calico CNI config cleanup"
    } elseif (-not (Test-Path "$env:CONTAINER_SANDBOX_MOUNT_POINT/$env:CNI_NET_DIR"))
    {
        Write-Host "$env:CNI_NET_DIR dir does not exist, skipping Calico CNI config cleanup"
    } else
    {
        $cniConfFile = "$env:CONTAINER_SANDBOX_MOUNT_POINT/$env:CNI_NET_DIR/10-calico.conf"
            if (Test-Path $cniConfFile) {
                Write-Host "Removing Calico CNI conf file at $cniConfFile ..."
                    rm $cniConfFile
            }

        if (Test-Path "$env:CNI_CONF_NAME") {
            $cniConfListFile = "$env:CONTAINER_SANDBOX_MOUNT_POINT/$env:CNI_NET_DIR/$env:CNI_CONF_NAME"
                if (Test-Path $cniConfListFile) {
                    Write-Host "Removing Calico CNI conf file at $cniConfListFile ..."
                        rm $cniConfListFile
                }
        }
    }


    if ("$env:CNI_BIN_DIR" -eq $null)
    {
        Write-Host "CNI_BIN_DIR env var not set, skipping Calico CNI binary cleanup"
    } elseif (-not (Test-Path "$env:CONTAINER_SANDBOX_MOUNT_POINT/$env:CNI_BIN_DIR"))
    {
        Write-Host "$env:CNI_BIN_DIR dir does not exist, skipping Calico CNI binary cleanup"
    } else
    {
        $cniBinPath = "$env:CONTAINER_SANDBOX_MOUNT_POINT/$env:CNI_BIN_DIR/calico*.exe"
            if (Test-Path $cniBinPath) {
                Write-Host "Removing Calico CNI binaries at $cniBinPath ..."
                    rm $cniBinPath
            }
    }
}

Write-Host "Stopping and removing Calico services if they are present..."
Remove-CalicoService CalicoConfd
Remove-CalicoService CalicoFelix
Remove-CalicoService CalicoNode
Remove-CalicoService CalicoUpgrade

# Only remove kube-proxy service if using Calico CNI (the recommended kube-proxy
# daemonset from sig-windows only supports Calico CNI)
if ("$env:CNI_PLUGIN_TYPE" -eq "Calico") {
    Write-Host "Stopping and removing kube-proxy service if it is present..."
    Write-Host "It is recommended to run kube-proxy as kubernetes daemonset instead"
    Remove-CalicoService kube-proxy
}

Write-Host "Logging containerd CNI bin and conf dir paths:"
Get-Content "$env:ProgramFiles/containerd/config.toml" | Select-String -Pattern "^(\s)*bin_dir = (.)*$"
Get-Content "$env:ProgramFiles/containerd/config.toml" | Select-String -Pattern "^(\s)*bin_dirs = (.)*$"
Get-Content "$env:ProgramFiles/containerd/config.toml" | Select-String -Pattern "^(\s)*conf_dir = (.)*$"

Get-Module 'calico' | Remove-Module -Force
Write-Host "Done."
