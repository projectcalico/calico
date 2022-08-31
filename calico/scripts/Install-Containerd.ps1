<#
.SYNOPSIS
Installs ContainerD on a Windows machine in preparation for joining the node to a Kubernetes cluster.

.DESCRIPTION
This script
- Verifies that Windows Features required for running containers are enabled (and enables then if they are not).
- Downloads ContainerD binaries at the version specified.
- Registers ContainerD as a windows service.

This is originally from https://github.com/kubernetes-sigs/sig-windows-tools/blob/master/kubeadm/scripts/Install-Containerd.ps1.
It has been adapted for Calico.

.PARAMETER ContainerDVersion
ContainerD version to download and use.

.EXAMPLE
PS> .\Install-Containerd.ps1 -ContainerDVersion 1.6.2 -CNIConfigPath "c:/etc/cni/net.d" -CNIBinPath "c:/opt/cni/bin"
#>

Param(
    [parameter(HelpMessage = "ContainerD version to use")]
    [string] $ContainerDVersion = "1.6.2",
    [parameter(HelpMessage = "Path to configure ContainerD to look for CNI config files. This should be set to the same path used for Calico for Windows.")]
    [string] $CNIConfigPath = "c:/etc/cni/net.d",
    [parameter(HelpMessage = "Path to configure ContainerD to look for CNI binaries. This should be set to the same path used for Calico for Windows.")]
    [string] $CNIBinPath = "c:/opt/cni/bin"
)

$ErrorActionPreference = 'Stop'

function DownloadFile($destination, $source) {
    Write-Host("Downloading $source to $destination")
    curl.exe --silent --fail -Lo $destination $source

    if (!$?) {
        Write-Error "Download $source failed"
        exit 1
    }
}

# The original script also included Hyper-V and Hyper-V-Powershell.
# However those are not needed by Calico for Windows.
$requiredWindowsFeatures = @(
    "Containers")

function ValidateWindowsFeatures {
    $allFeaturesInstalled = $true
    foreach ($feature in $requiredWindowsFeatures) {
        $f = Get-WindowsFeature -Name $feature
        if (-not $f.Installed) {
            Write-Warning "Windows feature: '$feature' is not installed."
            $allFeaturesInstalled = $false
        }
    }
    return $allFeaturesInstalled
}

if (-not (ValidateWindowsFeatures)) {
    Write-Output "Installing required windows features..."

    foreach ($feature in $requiredWindowsFeatures) {
        Install-WindowsFeature -Name $feature
    }

    Write-Output "Please reboot and re-run this script."
    exit 0
}

# Install 7Zip
Write-Output "Installing 7Zip"
Invoke-WebRequest https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.v2.psm1 -O $env:TEMP\helper.v2.psm1
ipmo $env:TEMP\helper.v2.psm1
Install-7Zip

Write-Output "Getting ContainerD binaries"
$global:ContainerDPath = "$env:ProgramFiles\containerd"
mkdir -Force $global:ContainerDPath | Out-Null
DownloadFile "$global:ContainerDPath\containerd.tar.gz" https://github.com/containerd/containerd/releases/download/v${ContainerDVersion}/containerd-${ContainerDVersion}-windows-amd64.tar.gz
tar.exe -xvf "$global:ContainerDPath\containerd.tar.gz" --strip=1 -C $global:ContainerDPath
$env:Path += ";$global:ContainerDPath"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
containerd.exe config default | Out-File "$global:ContainerDPath\config.toml" -Encoding ascii
#config file fixups
$config = Get-Content "$global:ContainerDPath\config.toml"
$config = $config -replace "bin_dir = (.)*$", "bin_dir = `"$CNIBinPath`""
$config = $config -replace "conf_dir = (.)*$", "conf_dir = `"$CNIConfigPath`""
$config | Set-Content "$global:ContainerDPath\config.toml" -Force

mkdir -Force $CNIBinPath | Out-Null
mkdir -Force $CNIConfigPath | Out-Null

Write-Output "Registering ContainerD as a service"
containerd.exe --register-service

Write-Output "Starting ContainerD service"
Start-Service containerd

Write-Output "Done - please remember to add '--cri-socket `"npipe:////./pipe/containerd-containerd`"' to your kubeadm join command"
