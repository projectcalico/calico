# Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
    [string]$NetworkName = "Calico"
)

$baseDir = "$PSScriptRoot\.."

# Import HNS libraries, included in the package.
ipmo -Force $baseDir\libs\hns\hns.psm1

. $baseDir\config.ps1

Write-Host "Running kub-proxy service."

# Now, wait for the Calico network to be created.
Write-Host "Waiting for HNS network $NetworkName to be created..."
while (-Not (Get-HnsNetwork | ? Name -EQ $NetworkName)) {
    Write-Debug "Still waiting for HNS network..."
    Start-Sleep 1
}
Write-Host "HNS network $NetworkName found."

# Determine the kube-proxy version.
$kubeProxyVer = $(c:\k\kube-proxy.exe --version)
$kubeProxyGE114 = $false
if ($kubeProxyVer -match "v([0-9])\.([0-9]+)") {
    $major = $Matches.1 -as [int]
    $minor = $Matches.2 -as [int]
    $kubeProxyGE114 = ($major -GT 1 -OR $major -EQ 1 -AND $minor -GE 14)
}

# Determine the windows version and build number for DSR support.
# OsHardwareAbstractionLayer is a version string like 10.0.17763.1432
$OSInfo = (Get-ComputerInfo  | select WindowsVersion, OsBuildNumber, OsHardwareAbstractionLayer)

# Windows supports DSR if
# - it is 1809 build 1432
# - it is 1903 or later
$min1809BuildSupportingDSR = (($OSInfo.OsHardwareAbstractionLayer.Split(".") | select-object -Last 1) -as [int]) -GE 1432
$windows1809 = (($OSInfo.WindowsVersion -as [int]) -EQ 1809 -And ($OSInfo.OsBuildNumber -as [int]) -GE 17763)
$windows1903OrNewer = (($OSInfo.WindowsVersion -as [int]) -GE 1903 -And ($OSInfo.OsBuildNumber -as [int]) -GE 18317)

$PlatformSupportDSR = ($windows1809 -And $min1809BuildSupportingDSR) -Or $windows1903OrNewer

# Build up the arguments for starting kube-proxy.
$argList = @(`
    "--hostname-override=$env:NODENAME", `
    "--v=4",`
    "--proxy-mode=kernelspace",`
    "--kubeconfig=""c:\k\config"""`
)
$extraFeatures = @()

if ($kubeProxyGE114 -And $PlatformSupportDSR) {
    Write-Host "Detected kube-proxy >= 1.14 and Windows version supporting DSR $OSInfo, enabling WinDSR feature gate."
    $extraFeatures += "WinDSR=true"
    $argList += "--enable-dsr=true"
} else {
    Write-Host "DSR feature is not supported."
}

$network = (Get-HnsNetwork | ? Name -EQ $NetworkName)
if ($network.Type -EQ "Overlay") {
    if (-NOT $kubeProxyGE114) {
        throw "Overlay network requires kube-proxy >= v1.14.  Detected $kubeProxyVer."
    }
    # This is a VXLAN network, kube-proxy needs to know the source IP to use for SNAT operations.
    Write-Host "Detected VXLAN network, waiting for Calico host endpoint to be created..."
    while (-Not (Get-HnsEndpoint | ? Name -EQ "Calico_ep")) {
        Start-Sleep 1
    }
    Write-Host "Host endpoint found."
    $sourceVip = (Get-HnsEndpoint | ? Name -EQ "Calico_ep").IpAddress
    $argList += "--source-vip=$sourceVip"
    $extraFeatures += "WinOverlay=true"

    # VXLAN on Windows doesn't support dualstack so disable explicitly. From k8s
    # 1.21 onwards IPv6DualStack defaults to true
    $extraFeatures += "IPv6DualStack=false"
}

if ($extraFeatures.Length -GT 0) {
    $featuresStr = $extraFeatures -join ","
    $argList += "--feature-gates=$featuresStr"
    Write-Host "Enabling feature gates: $extraFeatures."
}

# kube-proxy doesn't handle resync if there are pre-exisitng policies, clean them
# all out before (re)starting kube-proxy.
$policyLists = Get-HnsPolicyList
if ($policyLists) {
    $policyLists | Remove-HnsPolicyList
}

Write-Host "Start to run c:\k\kube-proxy.exe"
# We'll also pick up a network name env var from the Calico config file.  Override it
# since the value in the config file may be a regex.
$env:KUBE_NETWORK=$NetworkName
c:\k\kube-proxy.exe $argList
