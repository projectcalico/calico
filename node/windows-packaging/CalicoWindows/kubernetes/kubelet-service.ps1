# Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

Param(
    [string]$NodeIp="",
    [string]$InterfaceName="Ethernet"
)

$baseDir = "$PSScriptRoot\.."
. $baseDir\config.ps1
ipmo $baseDir\libs\calico\calico.psm1

Write-Host "Running kubelet service."
Write-Host "Using configured nodename: $env:NODENAME DNS: $env:DNS_NAME_SERVERS"

Write-Host "Auto-detecting node IP, looking for interface named 'vEthernet ($InterfaceName...'."
$na = Get-NetAdapter | ? Name -Like "vEthernet ($InterfaceName*" | ? Status -EQ Up
while ($na -EQ $null) {
    Write-Host "Waiting for interface named 'vEthernet ($InterfaceName...'."
    Start-Sleep 3
    $na = Get-NetAdapter | ? Name -Like "vEthernet ($InterfaceName*" | ? Status -EQ Up
}
$NodeIp = (Get-NetIPAddress -InterfaceAlias $na.ifAlias -AddressFamily IPv4).IPAddress
Write-Host "Detected node IP: $NodeIp."

$argList = @(`
    "--hostname-override=$env:NODENAME", `
    "--node-ip=$NodeIp", `
    "--v=4",`
    "--resolv-conf=""""",`
    "--enable-debugging-handlers",`
    "--cluster-dns=$env:DNS_NAME_SERVERS",`
    "--cluster-domain=cluster.local",`
    "--kubeconfig=c:\k\config",`
    "--hairpin-mode=promiscuous-bridge",`
    "--cgroups-per-qos=false",`
    "--logtostderr=true",`
    "--enforce-node-allocatable=""""",`
    "--kubeconfig=""c:\k\config"""`
)

# Configure kubelet for containerd if it is running.
if (Get-IsContainerdRunning)
{
    Write-Host "Detected containerd running, configuring kubelet for containerd"
    $argList += "--container-runtime=remote"
    $argList += "--container-runtime-endpoint=npipe:////.//pipe//containerd-containerd"
}
else
{
    #
    # These params are only applicable for the docker container runtime.
    #
    $argList += "--cni-bin-dir=""c:\k\cni"""
    $argList += "--cni-conf-dir=""c:\k\cni\config"""
    $argList += "--network-plugin=cni"
    $argList += "--pod-infra-container-image=k8s.gcr.io/pause:3.6"
    $argList += "--image-pull-progress-deadline=20m"
}

Write-Host "Start c:\k\kubelet.exe"
c:\k\kubelet.exe  $argList
