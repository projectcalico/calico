---
layout: null
---
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

<#
.DESCRIPTION
    This script installs and starts Calico services on a Windows node.

    Note: EKS requires downloading kubectl.exe to c:\k before running this script: https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html
#>

Param(
{%- if site.url == "https://docs.projectcalico.org" %}
    [parameter(Mandatory = $false)] $ReleaseBaseURL="https://github.com/projectcalico/calico/releases/download/{{site.data.versions.first.components["calico/node"].version}}/",
{%- else %}
    [parameter(Mandatory = $false)] $ReleaseBaseURL="{{site.url}}/files/windows/",
{%- endif %}
    [parameter(Mandatory = $false)] $ReleaseFile="calico-windows-{{site.data.versions.first.components["calico/node"].version}}.zip",
    [parameter(Mandatory = $false)] $KubeVersion="",
    [parameter(Mandatory = $false)] $DownloadOnly="no",
    [parameter(Mandatory = $false)] $Datastore="kubernetes",
    [parameter(Mandatory = $false)] $EtcdEndpoints="",
    [parameter(Mandatory = $false)] $ServiceCidr="10.96.0.0/12",
    [parameter(Mandatory = $false)] $DNSServerIPs="10.96.0.10"
)

function DownloadFiles()
{
    Write-Host "Downloading CNI binaries"
    md $BaseDir\cni\config -ErrorAction Ignore
    DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -Destination $BaseDir\cni\host-local.exe

    Write-Host "Downloading Windows Kubernetes scripts"
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 -Destination $BaseDir\hns.psm1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/InstallImages.ps1 -Destination $BaseDir\InstallImages.ps1
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile -Destination $BaseDir\Dockerfile
}

function PrepareDockerFile()
{
    # Update Dockerfile for windows
    $OSInfo = (Get-ComputerInfo  | select WindowsVersion, OsBuildNumber)
    $OSNumber = $OSInfo.WindowsVersion
    $ExistOSNumber = cat c:\k\Dockerfile | findstr.exe $OSNumber
    if (!$ExistOSNumber)
    {
        Write-Host "Update dockerfile for $OSNumber"

        $ImageWithOSNumber = "nanoserver:" + $OSNumber
        (get-content c:\k\Dockerfile) | foreach-object {$_ -replace "nanoserver", "$ImageWithOSNumber"} | set-content c:\k\Dockerfile
    }
}

function PrepareKubernetes()
{
    DownloadFiles
    PrepareDockerFile
    ipmo C:\k\hns.psm1

    # Prepare POD infra Images
    c:\k\InstallImages.ps1

    InstallK8sBinaries
}

function InstallK8sBinaries()
{
    Install-7Zip
    $Source = "" | Select Release
    $Source.Release=$KubeVersion
    InstallKubernetesBinaries -Destination $BaseDir -Source $Source
    cp c:\k\kubernetes\node\bin\*.exe c:\k
}

function GetPlatformType()
{
    # AKS
    $hnsNetwork = Get-HnsNetwork | ? Name -EQ azure
    if ($hnsNetwork.name -EQ "azure") {
        return ("azure")
    }

    # EKS
    $hnsNetwork = Get-HnsNetwork | ? Name -like "vpcbr*"
    if ($hnsNetwork.name -like "vpcbr*") {
        return ("eks")
    }

    # EC2
    $awsNodeName = Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/local-hostname -ErrorAction Ignore
    if (-Not [string]::IsNullOrEmpty($awsNodeName)) {
        return ("ec2")
    }
}

function GetCalicoKubeConfig()
{
    param(
      [parameter(Mandatory=$true)] $SecretName,
      [parameter(Mandatory=$false)] $KubeConfigPath = "c:\\k\\config"
    )

    # On EKS, we need to have AWS tools loaded for kubectl authentication.
    $eksAWSToolsModulePath="C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1"
    if (Test-Path $eksAWSToolsModulePath) {
        Write-Host "AWSPowerShell module exists, loading $eksAWSToolsModulePath ..."
        Import-Module $eksAWSToolsModulePath
    }

    $name=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret -n kube-system | findstr $SecretName | % { $_.Split(" ") | select -first 1 }
    if ([string]::IsNullOrEmpty($name)) {
        throw "$SecretName service account does not exist."
    }
    $ca=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret/$name -o jsonpath='{.data.ca\.crt}' -n kube-system
    $tokenBase64=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret/$name -o jsonpath='{.data.token}' -n kube-system
    $token=[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenBase64))

    $server=findstr https:// $KubeConfigPath

    (Get-Content c:\CalicoWindows\calico-kube-config.template).replace('<ca>', $ca).replace('<server>', $server.Trim()).replace('<token>', $token) | Set-Content c:\CalicoWindows\calico-kube-config -Force
}

function SetConfigParameters {
    param(
        [parameter(Mandatory=$true)] $OldString,
        [parameter(Mandatory=$true)] $NewString
    )

    (Get-Content c:\CalicoWindows\config.ps1).replace($OldString, $NewString) | Set-Content c:\CalicoWindows\config.ps1 -Force
}

function StartCalico()
{
    Write-Host "`nStart Calico...`n"

    pushd
    cd c:\CalicoWindows
    .\install-calico.ps1
    popd
    Write-Host "`nCalico Started`n"
}

$Backend="vxlan"
$BaseDir="c:\k"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$helper = "$BaseDir\helper.psm1"
$helperv2 = "$BaseDir\helper.v2.psm1"
md $BaseDir -ErrorAction Ignore
if (!(Test-Path $helper))
{
    Invoke-WebRequest https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.psm1 -O $BaseDir\helper.psm1
}
if (!(Test-Path $helperv2))
{
    Invoke-WebRequest https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.v2.psm1 -O $BaseDir\helper.v2.psm1
}
ipmo -force $helper
ipmo -force $helperv2

$platform=GetPlatformType

if (-Not [string]::IsNullOrEmpty($KubeVersion) -and $platform -NE "eks") {
    PrepareKubernetes
}

Write-Host "Download Calico for Windows release..."
DownloadFile -Url $ReleaseBaseURL/$ReleaseFile -Destination c:\calico-windows.zip
Write-Host "Unzip Calico for Windows release..."
Expand-Archive c:\calico-windows.zip c:\

Write-Host "Setup Calico for Windows..."
SetConfigParameters -OldString '<your datastore type>' -NewString $Datastore
SetConfigParameters -OldString '<your etcd endpoints>' -NewString "$EtcdEndpoints"
SetConfigParameters -OldString '<your service cidr>' -NewString $ServiceCidr
SetConfigParameters -OldString '<your dns server ips>' -NewString $DNSServerIPs
SetConfigParameters -OldString 'KUBECONFIG = "c:\k\config"' -NewString 'KUBECONFIG = "c:\CalicoWindows\calico-kube-config"'

if ($platform -EQ "azure") {
    Write-Host "Setup Calico for Windows for azure..."
    $Backend="none"
    SetConfigParameters -OldString 'CALICO_NETWORKING_BACKEND="vxlan"' -NewString 'CALICO_NETWORKING_BACKEND="none"'
    SetConfigParameters -OldString 'KUBE_NETWORK = "Calico.*"' -NewString 'KUBE_NETWORK = "azure.*"'
    GetCalicoKubeConfig -SecretName 'calico-windows'
}
if ($platform -EQ "eks") {
    $awsNodeName = Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/local-hostname -ErrorAction Ignore
    Write-Host "Setup Calico for Windows for eks, node name $awsNodeName ..."
    $Backend="none"
    $awsNodeNameQuote = """$awsNodeName"""
    SetConfigParameters -OldString '$(hostname).ToLower()' -NewString "$awsNodeNameQuote"
    SetConfigParameters -OldString 'CALICO_NETWORKING_BACKEND="vxlan"' -NewString 'CALICO_NETWORKING_BACKEND="none"'
    SetConfigParameters -OldString 'KUBE_NETWORK = "Calico.*"' -NewString 'KUBE_NETWORK = "vpc.*"'
    GetCalicoKubeConfig -SecretName 'calico-node' -KubeConfigPath C:\ProgramData\kubernetes\kubeconfig
}
if ($platform -EQ "ec2") {
    $awsNodeName = Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/local-hostname -ErrorAction Ignore
    Write-Host "Setup Calico for Windows for aws, node name $awsNodeName ..."
    $awsNodeNameQuote = """$awsNodeName"""
    SetConfigParameters -OldString '$(hostname).ToLower()' -NewString "$awsNodeNameQuote"
    GetCalicoKubeConfig -SecretName 'calico-node'
}
if([string]::IsNullOrEmpty($platform)) {
    GetCalicoKubeConfig -SecretName "calico-node"
}

if ($DownloadOnly -EQ "yes") {
    Write-Host "Dowloaded Calico for Windows. Update c:\CalicoWindows\config.ps1 and run c:\CalicoWindows\install-calico.ps1"
    Exit
}

StartCalico

if ($Backend -NE "none") {
    New-NetFirewallRule -Name KubectlExec10250 -Description "Enable kubectl exec and log" -Action Allow -LocalPort 10250 -Enabled True -DisplayName "kubectl exec 10250" -Protocol TCP -ErrorAction SilentlyContinue
}
