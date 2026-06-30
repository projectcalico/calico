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

. "$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/config.ps1"
ipmo "$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/libs/calico/calico.psm1" -Force
ipmo "$env:CONTAINER_SANDBOX_MOUNT_POINT/CalicoWindows/libs/hns/hns.psm1" -Force -DisableNameChecking

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

# Only clean up CNI artifacts if using Calico CNI
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

    # Clean up HNS networks if node has rebooted. Must occur before CNI re-install.
    if ($env:CALICO_NETWORKING_BACKEND -EQ "windows-bgp" -OR $env:CALICO_NETWORKING_BACKEND -EQ "vxlan")
    {
        Write-Host "Calico $env:CALICO_NETWORKING_BACKEND networking enabled."

        # Check if the node has been rebooted.  If so, the HNS networks will be in unknown state so we need to
        # clean them up and recreate them.
        $lastBootTime = Get-LastBootTime
        $prevLastBootTime = Get-StoredLastBootTime
        Write-Output "calico-install: StoredLastBootTime $prevLastBootTime, CurrentLastBootTime $lastBootTime"
        if ($prevLastBootTime -NE $lastBootTime)
        {
            if ((Get-HNSNetwork | ? Type -NE nat))
            {
                Write-Host "First time Calico has run since boot up, cleaning out any old network state."
                Get-HNSNetwork | ? Type -NE nat | Remove-HNSNetwork
                do
                {
                    Write-Host "Waiting for network deletion to complete."
                    Start-Sleep 1
                } while ((Get-HNSNetwork | ? Type -NE nat))
            }

            # After deletion of all hns networks, wait for an interface to have an IP that is not a 169.254.0.0/16 (or 127.0.0.0/8) address,
            # before creation of External network.
            $isValidIP = $false
            $timeout = $env:STARTUP_VALID_IP_TIMEOUT
            $IPRegEx1='(^127\.0\.0\.)'
            $IPRegEx2='(^169\.254\.)'
            while(!($isValidIP) -AND ($timeout -gt 0))
            {
                $IPAddress = (Get-NetIPAddress -AddressFamily IPv4).IPAddress
                Write-Host "`nTimeout Remaining: $timeout sec"
                Write-Host "List of IP Address before initialising Calico: $IPAddress"
                Foreach ($ip in $IPAddress)
                {
                    if (($ip -NotMatch $IPRegEx1) -AND ($ip -NotMatch $IPRegEx2))
                    {
                        $isValidIP = $true
                        Write-Host "`nFound valid IP: $ip"
                        break
                    }
                }
                if (!($isValidIP))
                {
                    Start-Sleep -s 5
                    $timeout = $timeout - 5
                }
            }
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
