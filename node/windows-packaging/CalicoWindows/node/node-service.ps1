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

# This script is run from the main Calico folder.
. .\config.ps1

ipmo .\libs\calico\calico.psm1 -Force
ipmo .\libs\hns\hns.psm1 -Force

$lastBootTime = Get-LastBootTime
$Stored = Get-StoredLastBootTime
Write-Host "StoredLastBootTime $Stored, CurrentLastBootTime $lastBootTime"

$timeout = $env:STARTUP_VALID_IP_TIMEOUT
$vxlanAdapter = $env:VXLAN_ADAPTER

# Autoconfigure the IPAM block mode.
if ($env:CNI_IPAM_TYPE -EQ "host-local") {
    $env:USE_POD_CIDR = "true"
} else {
    $env:USE_POD_CIDR = "false"
}

$platform = Get-PlatformType

if ($env:CALICO_NETWORKING_BACKEND -EQ "windows-bgp" -OR $env:CALICO_NETWORKING_BACKEND -EQ "vxlan")
{
    Write-Host "Calico $env:CALICO_NETWORKING_BACKEND networking enabled."

    # Check if the node has been rebooted.  If so, the HNS networks will be in unknown state so we need to
    # clean them up and recreate them.
    $prevLastBootTime = Get-StoredLastBootTime
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

    # Create a bridge to trigger a vSwitch creation. Do this only once
    Write-Host "`nStart creating vSwitch. Note: Connection may get lost for RDP, please reconnect...`n"
    while (!(Get-HnsNetwork | ? Name -EQ "External"))
    {
        if ($env:CALICO_NETWORKING_BACKEND -EQ "vxlan") {
            # FIXME Firewall rule port?
            New-NetFirewallRule -Name OverlayTraffic4789UDP -Description "Overlay network traffic UDP" -Action Allow -LocalPort 4789 -Enabled True -DisplayName "Overlay Traffic 4789 UDP" -Protocol UDP -ErrorAction SilentlyContinue
            $result = New-HNSNetwork -Type Overlay -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -SubnetPolicies @(@{Type = "VSID"; VSID = 9999; }) -AdapterName $vxlanAdapter -Verbose
        }
        else
        {
            $result = New-HNSNetwork -Type L2Bridge -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -Verbose
        }
        if ($result.Error -OR (!$result.Success)) {
            Write-Host "Failed to create network, retrying..."
            Start-Sleep 1
        } else {
            break
        }
    }

    # Wait for the management IP to show up and then give an extra grace period for
    # the networking stack to settle down.
    $mgmtIP = Wait-ForManagementIP "External"
    Write-Host "Management IP detected on vSwitch: $mgmtIP."
    Start-Sleep 10

    if (($platform -EQ "ec2") -or ($platform -EQ "gce")) {
        Set-MetaDataServerRoute -mgmtIP $mgmtIP
    }

    if ($env:CALICO_NETWORKING_BACKEND -EQ "windows-bgp") {
        Write-Host "Restarting BGP service to pick up any interface renumbering..."
        Restart-Service RemoteAccess
    }
}

# For Windows, we expect the nodename file to exist in the root directory of the
# Calico for Windows installation. The CNI config field 'nodename_file' will
# always be $RootDir\nodename
$env:CALICO_NODENAME_FILE = "$RootDir\nodename"

# We use this setting as a trigger for the other scripts to proceed.
Set-StoredLastBootTime $lastBootTime
$Stored = Get-StoredLastBootTime
Write-Host "Stored new lastBootTime $Stored"

# The old version of Calico upgrade service may still be running.
while (Get-UpgradeService)
{

    Remove-UpgradeService
    if ($LastExitCode -EQ 0) {
        Write-Host "CalicoUpgrade service removed"
        break
    }
    Start-Sleep 5
    Write-Host "Failed to clean up old CalicoUpgrade service, retrying..."
}

# Run the startup script whenever kubelet (re)starts. This makes sure that we refresh our Node annotations if
# kubelet recreates the Node resource.
$kubeletPid = -1
while ($True)
{
    try
    {
        # Run calico-node.exe if kubelet starts/restarts
        $currentKubeletPid = (Get-Process -Name kubelet -ErrorAction Stop).id
        if ($currentKubeletPid -NE $kubeletPid)
        {
            Write-Host "Kubelet has (re)started, (re)initialising the node..."
            $kubeletPid = $currentKubeletPid
            while ($true)
            {
                .\calico-node.exe -startup
                if ($LastExitCode -EQ 0)
                {
                    Write-Host "Calico node initialisation succeeded; monitoring kubelet for restarts..."
                    break
                }

                Write-Host "Calico node initialisation failed, will retry..."
                Start-Sleep 1
            }
        }
    }
    catch
    {
        Write-Host "Kubelet not running, waiting for Kubelet to start..."
        $kubeletPid = -1
    }

    if (!(Get-UpgradeService)) {
        # If upgrade service has not been running, check if we should run upgrade service.
        .\calico-node.exe -should-install-windows-upgrade
        if ($LastExitCode -EQ 0) {
            Install-UpgradeService
            Start-Service CalicoUpgrade
        }
    }

    Start-Sleep 10
}
