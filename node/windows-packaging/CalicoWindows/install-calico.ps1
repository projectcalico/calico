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

# Force powershell to run in 64-bit mode .
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    write-warning "This script requires PowerShell 64-bit, relaunching..."
    if ($myInvocation.Line) {
        &"$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile $myInvocation.Line
    }else{
        &"$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -file "$($myInvocation.InvocationName)" $args
    }
    exit $lastexitcode
}

ipmo "$PSScriptRoot\libs\calico\calico.psm1" -Force

# Ensure our scripts are allowed to run.
Unblock-File $PSScriptRoot\*.ps1

. $PSScriptRoot\config.ps1

Test-CalicoConfiguration

Install-NodeService
Install-FelixService
if ($env:CALICO_NETWORKING_BACKEND -EQ "vxlan")
{
    if (($env:VXLAN_VNI -as [int]) -lt 4096)
    {
        Write-Host "Windows does not support VXLANVNI < 4096."
        exit 1
    }
    Install-CNIPlugin
}
elseif ($env:CALICO_NETWORKING_BACKEND -EQ "windows-bgp")
{
    Install-ConfdService
    Install-CNIPlugin
}
else
{
    Write-Host "Using third party CNI plugin."
}

Write-Host "Starting Calico..."
Write-Host "This may take several seconds if the vSwitch needs to be created."

Start-Service CalicoNode
Wait-ForCalicoInit
Start-Service CalicoFelix

if ($env:CALICO_NETWORKING_BACKEND -EQ "windows-bgp")
{
    Start-Service CalicoConfd
}

while ((Get-Service | where Name -Like 'Calico*' | where Status -NE Running) -NE $null) {
    Write-Host "Waiting for the Calico services to be running..."
    Start-Sleep 1
}

Write-Host "Done, the Calico services are running:"
Get-Service | where Name -Like 'Calico*'
