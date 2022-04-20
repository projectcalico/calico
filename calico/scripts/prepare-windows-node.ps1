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
#
# This script prepares a Windows node. Its main steps are:
# - Download the Calico for Windows files needed to install kubelet.
# - Install and start containerd.
# - Install and start kubelet.
#
# Before running this script:
# - Prepare a kubeconfig file on the Windows node for kubelet to use.
#
# Example usage:
# .\prepare-windows-node.ps1 -K8sVersion 1.23.4 -DNSNameServers 10.96.0.10

Param(
    # The version of Kubernetes binaries to install. E.g. 1.23.4"
    [parameter(Mandatory = $true)] $K8sVersion,

    # The DNS nameserver for kubelet to use. E.g. your cluster's kube-dns cluster IP.
    [parameter(Mandatory = $true)] $DNSNameServers,

    # The kubeconfig file for kubelet to use.
    [parameter(Mandatory = $false)] $KubeconfigPath = "c:\k\config",

    # The CNI conf dir to use for containerd.
    [parameter(Mandatory = $false)] $CNIConfDir = "c:/etc/cni/net.d",

    # The CNI bin dir to use for containerd.
    [parameter(Mandatory = $false)] $CNIBinDir = "c:/opt/cni/bin",

    # Provide the nodename used by kubelet. If not set, defaults to $(hostname).ToLower()
    [parameter(Mandatory = $false)] $Nodename = "",

    # The version of containerd to install. E.g. 1.6.2.
    [parameter(Mandatory = $false)] $ContainerdVersion = "1.6.2",

    # If $true, existing files are overwritten.
    [parameter(Mandatory = $false)] $Overwrite = $false
)

$ErrorActionPreference = "Stop"
$rootDir = "c:\CalicoWindows"
# Otherwise download takes too long to download
$ProgressPreference = 'SilentlyContinue'
$kubeletPath = "c:\k\kubelet.exe"

if ((Get-Service | where Name -EQ 'kubelet') -NE $null) {
  Write-Host "kubelet service already exists."
  exit 1
}

if ((Get-Service | where Name -EQ 'containerd') -NE $null) {
  Write-Host "containerd service already exists."
  exit 1
}
if (-not (Test-Path $KubeconfigPath)) {
  Write-Host "The kubeconfig file $KubeconfigPath does not exist. A kubeconfig file must be provided for kubelet."
  exit 1
}

if ((Test-Path $kubeletPath) -and (-not $Overwrite)) {
  Write-Host "kubelet binary already exists at $kubeletPath. Remove it or re-run the script with '-Overwrite true' to overwrite it"
  exit 1
}

if ((Test-Path $rootDir) -and (-not $Overwrite)) {
  Write-Host "$rootDir exists. Remove it or re-run the script with '-Overwrite true' to overwrite those files."
  Write-Host "WARNING: this will overwrite $rootDir\config.ps1."
  exit 1
}

Write-Host "Create root dir $rootDir and supporting files to install kube services..."
mkdir $rootDir -Force | Out-Null
mkdir $rootDir\libs\calico -Force | Out-Null
mkdir $rootDir\kubernetes -Force | Out-Null

$baseUrl = "https://raw.githubusercontent.com/projectcalico/calico/8176616948416e697bb708667dd54ad6fca1884f/node/windows-packaging/"
curl -o $rootDir\config.ps1 "$baseUrl/CalicoWindows/config.ps1"
curl -o $rootDir\libs\calico\calico.psm1 "$baseUrl/CalicoWindows/libs/calico/calico.psm1"
curl -o $rootDir\kubernetes\kubelet-service.ps1 "$baseUrl/CalicoWindows/kubernetes/kubelet-service.ps1"
curl -o $rootDir\kubernetes\install-kube-services.ps1 "$baseUrl/CalicoWindows/kubernetes/install-kube-services.ps1"
curl -o $rootDir\kubernetes\uninstall-kube-services.ps1 "$baseUrl/CalicoWindows/kubernetes/uninstall-kube-services.ps1"
curl -o $env:TEMP\nssm.zip "$baseUrl/nssm-2.24.zip"
Expand-Archive -Force -Path $env:TEMP\nssm.zip -DestinationPath $env:TEMP\
Copy-Item $env:TEMP\nssm-2.24 -Destination $rootDir -Force -Recurse
ipmo $rootDir\libs\calico\calico.psm1 -Force

#
# Install containerd
#
Write-Host "Importing helper module..."
Invoke-WebRequest https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.v2.psm1 -O $rootDir\helper.v2.psm1
ipmo $rootDir\helper.v2.psm1 -Force

Write-Host "Installing 7zip to extract containerd archive..."
Install-7zip

mkdir $CNIBinDir -Force | Out-Null
mkdir $CNIConfDir -Force | Out-Null

Write-Host "Downloading containerd..."
$containerdPath = "$env:ProgramFiles\containerd"
mkdir $containerdPath -Force | Out-Null
curl https://github.com/containerd/containerd/releases/download/v$ContainerdVersion/containerd-$ContainerdVersion-windows-amd64.tar.gz -o $env:TEMP\containerd-windows-amd64.tar.gz
Write-Host "Extracting containerd ..."
tar.exe xvf $env:TEMP\containerd-windows-amd64.tar.gz --strip=1 -C $containerdPath

$env:Path += ";$containerdPath"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

Write-Host "Writing containerd config to $containerdPath\config.toml ..."
containerd.exe config default | Out-File "$containerdPath\config.toml" -Encoding ascii
# Replace containerd config's default CNI bin and conf values.
# From: https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/Install-Containerd.ps1 
$config = Get-Content "$containerdPath\config.toml"
$config = $config -replace "bin_dir = (.)*$", "bin_dir = `"$CNIBinDir`""
$config = $config -replace "conf_dir = (.)*$", "conf_dir = `"$CNIConfDir`""
$config | Set-Content "$containerdPath\config.toml" -Force

Set-EnvVarIfNotSet -var "CNI_BIN_DIR" -defaultValue $CNIBinDir
Set-EnvVarIfNotSet -var "CNI_CONF_DIR" -defaultValue $CNIConfDir

Write-Host "Starting containerd..."
containerd.exe --register-service
Start-Service containerd

#
# Download kubelet.exe based on environment variable
#
mkdir c:\k -Force | Out-Null
$url = "https://dl.k8s.io/v${K8sVersion}/bin/windows/amd64/kubelet.exe"
Write-Host "Downloading kubelet.exe from $url to $kubeletPath" 
curl $url -o $kubeletPath

#
# Setup and install kubelet service
#
ipmo $rootDir\libs\calico\calico.psm1 -Force
if ($Nodename -EQ "") {
    $Nodename = $(hostname).ToLower()
}
Set-EnvVarIfNotSet -var "NODENAME" -defaultValue $Nodename
Set-EnvVarIfNotSet -var "DNS_NAME_SERVERS" -defaultValue "$DNSNameServers"

& "$rootDir\kubernetes\install-kube-services.ps1" -Service kubelet
Start-Service kubelet

