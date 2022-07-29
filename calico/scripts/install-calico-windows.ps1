---
layout: null
---
# Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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
    This script installs and starts {{site.prodname}} services on a Windows node.

    Note: EKS requires downloading kubectl.exe to c:\k before running this script: https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html
#>

Param(
    # Note: we don't publish a release artifact for the "master" branch. To test
    # against master, build calico-windows.zip from projectcalico/node.
{%- if site.url contains "projectcalico" %}
    [parameter(Mandatory = $false)] $ReleaseBaseURL="https://github.com/projectcalico/calico/releases/download/{{site.data.versions.first.components["calico/node"].version}}/",
{%- else %}
    [parameter(Mandatory = $false)] $ReleaseBaseURL="{{site.url}}/files/windows/",
{%- endif %}
    [parameter(Mandatory = $false)] $ReleaseFile="calico-windows-{{site.data.versions.first.components["calico/node"].version}}.zip",
    [parameter(Mandatory = $false)] $KubeVersion="",
    [parameter(Mandatory = $false)] $DownloadOnly="no",
    [parameter(Mandatory = $false)] $StartCalico="yes",
    # As of Kubernetes version v1.24.0, service account token secrets are no longer automatically created. But this installation script uses that secret
    # to generate a kubeconfig so default to creating the calico-node token secret if it doesn't exist.
    [parameter(Mandatory = $false)] $AutoCreateServiceAccountTokenSecret="yes",
    [parameter(Mandatory = $false)] $Datastore="kubernetes",
    [parameter(Mandatory = $false)] $EtcdEndpoints="",
    [parameter(Mandatory = $false)] $EtcdTlsSecretName="",
    [parameter(Mandatory = $false)] $EtcdKey="",
    [parameter(Mandatory = $false)] $EtcdCert="",
    [parameter(Mandatory = $false)] $EtcdCaCert="",
    [parameter(Mandatory = $false)] $ServiceCidr="10.96.0.0/12",
    [parameter(Mandatory = $false)] $DNSServerIPs="10.96.0.10",
    [parameter(Mandatory = $false)] $CalicoBackend=""
)

function DownloadFiles()
{
    Write-Host "Creating CNI directory"
    md $BaseDir\cni\config -ErrorAction Ignore

    Write-Host "Downloading Windows Kubernetes scripts"
    DownloadFile -Url  https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1 -Destination $BaseDir\hns.psm1
}

function PrepareKubernetes()
{
    DownloadFiles
    ipmo -DisableNameChecking C:\k\hns.psm1
    InstallK8sBinaries

    # Prepull and tag the pause image for docker
    if (-not (Get-IsContainerdRunning)) {
        # If containerd is not running we assume the installation should be
        # configured for docker. But in this case, docker has to be running.
        $svc = Get-Service | where Name -EQ 'docker'
        if ($svc -EQ $null) {
            Write-Host "Docker service is not installed. Cannot prepare kubernetes pause image."
            exit 1
        }
        if ($svc.Status -NE 'Running') {
            Write-Host "Docker service is not running. Cannot prepare kubernetes pause image. Run 'Start-Service docker' and try again."
            exit 1
        }
        $pause = "mcr.microsoft.com/oss/kubernetes/pause:3.6"
        docker pull $pause
        docker tag $pause kubeletwin/pause
    }
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
        return ("aks")
    }

    # EKS
    $hnsNetwork = Get-HnsNetwork | ? Name -like "vpcbr*"
    if ($hnsNetwork.name -like "vpcbr*") {
        return ("eks")
    }

    # EC2
    $restError = $null
    Try {
        $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "300"} -Method PUT -Uri http://169.254.169.254/latest/api/token -ErrorAction Ignore
        $awsNodeName = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri http://169.254.169.254/latest/meta-data/local-hostname -ErrorAction Ignore
    } Catch {
        $restError = $_
    }
    if ($restError -eq $null) {
        return ("ec2")
    }

    # GCE
    $restError = $null
    Try {
        $gceNodeName = Invoke-RestMethod -UseBasicParsing -Headers @{"Metadata-Flavor"="Google"} "http://metadata.google.internal/computeMetadata/v1/instance/hostname" -ErrorAction Ignore
    } Catch {
        $restError = $_
    }
    if ($restError -eq $null) {
        return ("gce")
    }

    return ("bare-metal")
}

function GetBackendType()
{
    param(
        [parameter(Mandatory=$true)] $CalicoNamespace,
        [parameter(Mandatory=$false)] $KubeConfigPath = "$RootDir\calico-kube-config"
    )

    if (-Not [string]::IsNullOrEmpty($CalicoBackend)) {
        return $CalicoBackend
    }

    # For hostprocess installs, if CALICO_NETWORKING_BACKEND is set to a valid value, try to use it.
    if ($env:CONTAINER_SANDBOX_MOUNT_POINT -and $env:CALICO_NETWORKING_BACKEND) {
        $backend = $env:CALICO_NETWORKING_BACKEND
        if (($backend -eq "vxlan") -or ($backend -eq "windows-bgp")) {
            return $backend
        }

        if ($backend -NE $null) {
            Write-Host "Invalid Calico backend type: $backend. Set CALICO_NETWORKING_BACKEND in calico-windows-config in calico-system namespace to one of: 'vxlan', 'windows-bgp'"
            exit 1
        }

        # If CALICO_NETWORKING_BACKEND is not set we can only continue if the
        # kubeconfig and kubectl.exe both exist.
        if ((-not (Test-Path $KubeConfigPath)) -or (-not (Test-Path "c:\k\kubectl.exe"))) {
            Write-Host "No CALICO_NETWORKING_BACKEND provided. Set CALICO_NETWORKING_BACKEND in calico-windows-config in calico-system namespace to one of: 'vxlan', 'windows-bgp'"
            exit 1
        }

        # If we reach here, we can continue auto-detecting the backend type.
    }

    # Auto detect backend type
    if ($Datastore -EQ "kubernetes") {
        $encap=c:\k\kubectl.exe --kubeconfig="$KubeConfigPath" get felixconfigurations.crd.projectcalico.org default -o jsonpath='{.spec.ipipEnabled}'
        if ($encap -EQ "true") {
            throw "{{site.prodname}} on Linux has IPIP enabled. IPIP is not supported on Windows nodes."
        }

        # Check FelixConfig first.
        $encap=c:\k\kubectl.exe --kubeconfig="$KubeConfigPath" get felixconfigurations.crd.projectcalico.org default -o jsonpath='{.spec.vxlanEnabled}'
        if ($encap -EQ "true") {
            return ("vxlan")
        } elseif ($encap -EQ "false") {
            return ("bgp")
        } else {
           # If any IPPool has IPIP enabled, we need to exit the installer. The
           # IPIP-enabled might not be assigned to this Windows node but we can't
           # verify that easily by looking at the nodeSelector.
           $ipipModes = c:\k\kubectl.exe --kubeconfig="$KubeConfigPath" get ippools.crd.projectcalico.org -o jsonpath='{.items[*].spec.ipipMode}'
           $ipipEnabled = $ipipModes | Select-String -pattern '(Always)|(CrossSubnet)'
           if ($ipipEnabled -NE $null) {
               throw "Failed to auto detect backend type. IPIP is not supported on Windows nodes but found IP pools with IPIP enabled. Rerun install script with the CalicoBackend param provided"
           }

           # If FelixConfig does not have vxlanEnabled then check the IPPools and see if any of them have enabled vxlan.
           $vxlanModes=c:\k\kubectl.exe --kubeconfig="$KubeConfigPath" get ippools.crd.projectcalico.org -o jsonpath='{.items[*].spec.vxlanMode}'
           $vxlanEnabled = $vxlanModes | Select-String -pattern '(Always)|(CrossSubnet)'
           if ($vxlanEnabled -NE $null) {
               return ("vxlan")
           } else {
               return ("bgp")
           }
        }
    } else {
        $CalicoBackend=c:\k\kubectl.exe --kubeconfig="$KubeConfigPath" get configmap calico-config -n $CalicoNamespace -o jsonpath='{.data.calico_backend}'
        if ($CalicoBackend -EQ "vxlan") {
            return ("vxlan")
        }
        return ("bgp")
    }
}

function GetCalicoNamespace() {
    param(
      [parameter(Mandatory=$false)] $KubeConfigPath = "c:\\k\\config"
    )

    # If we are running inside a HostProcess container then return our
    # namespace.
    if ($env:CONTAINER_SANDBOX_MOUNT_POINT) {
        $ns = Get-Content -Raw -Path $env:CONTAINER_SANDBOX_MOUNT_POINT/var/run/secrets/kubernetes.io/serviceaccount/namespace
        write-host ("Install script is running in a HostProcess container. This namespace is {0}" -f $ns)
        return $ns
    }

    $ErrorActionPreference = 'Continue'
    $name=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get ns calico-system
    $ErrorActionPreference = 'Stop'
    if ([string]::IsNullOrEmpty($name)) {
        write-host "Calico running in kube-system namespace"
        return ("kube-system")
    }
    write-host "Calico running in calico-system namespace"
    return ("calico-system")
}

function GetCalicoKubeConfig()
{
    param(
      [parameter(Mandatory=$true)] $CalicoNamespace,
      [parameter(Mandatory=$false)] $SecretNamePrefix = "calico-node",
      [parameter(Mandatory=$false)] $KubeConfigPath = "c:\\k\\config"
    )

    # On EKS, we need to have AWS tools loaded for kubectl authentication.
    $eksAWSToolsModulePath="C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1"
    if (Test-Path $eksAWSToolsModulePath) {
        Write-Host "AWSPowerShell module exists, loading $eksAWSToolsModulePath ..."
        Import-Module $eksAWSToolsModulePath
    }

    # If we are running inside a HostProcess container then we already have
    # access to the serviceaccount token and ca cert.
    if ($env:CONTAINER_SANDBOX_MOUNT_POINT) {
        Write-Host "Install script is running in a HostProcess container, using mounted serviceaccount ca cert and token."
        # CA needs to be base64-encoded.
        $ca = Get-Content -Raw -Path $env:CONTAINER_SANDBOX_MOUNT_POINT/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        $ca = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ca))
        # But not the token.
        $token = Get-Content -Path $env:CONTAINER_SANDBOX_MOUNT_POINT/var/run/secrets/kubernetes.io/serviceaccount/token

        # KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are used if both
        # provided. If this is not the case, fallback to using $KubeConfigPath
        # if it exists.
        $k8sHost = $env:KUBERNETES_SERVICE_HOST
        $k8sPort = $env:KUBERNETES_SERVICE_PORT
        if ($k8sHost -and $k8sPort) {
            $server = "server: https://{0}:{1}" -f $k8sHost, $k8sPort
            Write-Host "Using KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT env variables for kubeconfig. $server"
        } elseif (Test-Path $KubeConfigPath) {
            $server=findstr https:// $KubeConfigPath
            Write-Host ("Using existing kubeconfig at $KubeConfigPath for API server host and port. {0}" -f $server.Trim())
        } else {
            Write-Host "Cannot determine API server host and port. Add KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT to calico-windows-config in calico-system namespace"
            exit 1
        }
    } else {
        $name=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret -n $CalicoNamespace --field-selector=type=kubernetes.io/service-account-token --no-headers -o custom-columns=":metadata.name" | findstr $SecretName | select -first 1
        if ([string]::IsNullOrEmpty($name)) {
            throw "$SecretName service account does not exist."
        $ErrorActionPreference = 'Continue'
        $secretName=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret -n $CalicoNamespace --field-selector=type=kubernetes.io/service-account-token --no-headers -o custom-columns=":metadata.name" | findstr $SecretNamePrefix | select -first 1
        $ErrorActionPreference = 'Stop'
        if ([string]::IsNullOrEmpty($secretName)) {
            if (-Not $AutoCreateServiceAccountTokenSecret) {
                throw "$SecretName service account token secret does not exist."
            } else {
                # Otherwise create the serviceaccount token secret.
                $secretName = "calico-node-token"
                CreateTokenAccountSecret -Name $secretName -Namespace $CalicoNamespace -KubeConfigPath $KubeConfigPath
            }
        }
        # CA from the k8s secret is already base64-encoded.
        $ca=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret/$secretName -o jsonpath='{.data.ca\.crt}' -n $CalicoNamespace
        # Token from the k8s secret is base64-encoded but we need the jwt token.
        $tokenBase64=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret/$secretName -o jsonpath='{.data.token}' -n $CalicoNamespace
        $token=[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenBase64))

        $server=findstr https:// $KubeConfigPath
    }

    (Get-Content $RootDir\calico-kube-config.template).replace('<ca>', $ca).replace('<server>', $server.Trim()).replace('<token>', $token) | Set-Content $RootDir\calico-kube-config -Force
}

function CreateTokenAccountSecret()
{
    param(
      [parameter(Mandatory=$true)] $Name,
      [parameter(Mandatory=$true)] $Namespace,
      [parameter(Mandatory=$false)] $KubeConfigPath = "c:\\k\\config"
    )

    $tempFile = New-TemporaryFile
    Write-Host "Created temp file ${tempFile}"

    $yaml=@"
apiVersion: v1
kind: Secret
metadata:
  name: $Name
  namespace: $Namespace
  annotations:
    kubernetes.io/service-account.name: calico-node
type: kubernetes.io/service-account-token
"@
    Set-Content -Path $tempFile.FullName -value $yaml
    c:\k\kubectl --kubeconfig $KubeConfigPath apply -f $tempFile.FullName
}

function EnableWinDsrForEKS()
{
    $OSInfo = (Get-ComputerInfo  | select WindowsVersion, OsBuildNumber)
    $supportsDSR = Get-IsDSRSupported

    if (-Not $supportsDSR) {
        Write-Host "WinDsr is not supported ($OSInfo)"
        return
    }

    # Update and restart kube-proxy if WinDSR is not enabled by default.
    $Path = Get-CimInstance -Query 'select * from win32_service where name="kube-proxy"' | Select -ExpandProperty pathname
    if ($Path -like "*--enable-dsr=true*") {
        Write-Host "WinDsr is enabled by default."
    } else {
        $UpdatedPath = $Path + " --enable-dsr=true --feature-gates=WinDSR=true"
        Get-CimInstance win32_service -filter 'Name="kube-proxy"' | Invoke-CimMethod -Name Change -Arguments @{PathName=$UpdatedPath}
        Restart-Service -name "kube-proxy"
        Write-Host "WinDsr has been enabled for kube-proxy."
    }
}

function SetupEtcdTlsFiles()
{
    param(
      [parameter(Mandatory=$true)] $CalicoNamespace,
      [parameter(Mandatory=$true)] $SecretName,
      [parameter(Mandatory=$false)] $KubeConfigPath = "c:\\k\\config"
    )

    $path = "$RootDir\etcd-tls"

    $ErrorActionPreference = 'Continue'
    $found=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret/$SecretName -n $CalicoNamespace
    $ErrorActionPreference = 'Stop'
    if ([string]::IsNullOrEmpty($found)) {
        throw "$SecretName does not exist."
    }

    $keyB64=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret/$SecretName -o jsonpath='{.data.etcd-key}' -n $CalicoNamespace
    $certB64=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret/$SecretName -o jsonpath='{.data.etcd-cert}' -n $CalicoNamespace
    $caB64=c:\k\kubectl.exe --kubeconfig=$KubeConfigPath get secret/$SecretName -o jsonpath='{.data.etcd-ca}' -n $CalicoNamespace

    New-Item -Type Directory -Path $path -Force

    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($keyB64)) | Set-Content "$path\server.key" -Force
    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($certB64)) | Set-Content "$path\server.crt" -Force
    [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($caB64)) | Set-Content "$path\ca.crt" -Force

    $script:EtcdKey = "$path\server.key"
    $script:EtcdCert = "$path\server.crt"
    $script:EtcdCaCert = "$path\ca.crt"
}

function SetAKSCalicoStaticRules {
    $fileName  = [Io.path]::Combine("$RootDir", "static-rules.json")
    echo '{
    "Provider": "AKS",
    "Rules": [
        {
            "Name": "EndpointPolicy",
            "Rule": {
                "Action": "Block",
                "Direction": "Out",
                "Id": "block-wireserver",
                "Priority": 200,
                "Protocol": 6,
                "RemoteAddresses": "168.63.129.16/32",
                "RemotePorts": "80",
                "RuleType": "Switch",
                "Type": "ACL"
            }
        }
    ],
    "version": "0.1.0"
}' | Out-File -encoding ASCII -filepath $fileName
}

function InstallCalico()
{
    Write-Host "`nStart Calico for Windows install...`n"

    pushd
    cd $RootDir
    .\install-calico.ps1
    popd
    Write-Host "`nCalico for Windows installed`n"
}

# kubectl errors are expected, so there are places where this is reset to "Continue" temporarily
$ErrorActionPreference = "Stop"

$BaseDir="c:\k"
$RootDir="c:\CalicoWindows"

# If this script is run from a HostProcess container then the installation archive
# will be in the mount point.
if ($env:CONTAINER_SANDBOX_MOUNT_POINT) {
$CalicoZip="$env:CONTAINER_SANDBOX_MOUNT_POINT\calico-windows.zip"
} else {
$CalicoZip="c:\calico-windows.zip"
}

# Must load the helper modules before doing anything else.
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
ipmo -force -DisableNameChecking $helper
ipmo -force -DisableNameChecking $helperv2

if (!(Test-Path $CalicoZip))
{
    Write-Host "$CalicoZip not found, downloading Calico for Windows release..."
    DownloadFile -Url $ReleaseBaseURL/$ReleaseFile -Destination c:\calico-windows.zip
}

$platform=GetPlatformType

if ((Get-Service -exclude 'CalicoUpgrade' | where Name -Like 'Calico*' | where Status -EQ Running) -NE $null) {
    Write-Host "Calico services are still running. In order to re-run the installation script, stop the CalicoNode and CalicoFelix services or uninstall them by running: $RootDir\uninstall-calico.ps1"
    Exit
}

Remove-Item $RootDir -Force  -Recurse -ErrorAction SilentlyContinue
Write-Host "Unzip Calico for Windows release..."
Expand-Archive -Force $CalicoZip c:\
ipmo -force $RootDir\libs\calico\calico.psm1

# This comes after we import calico.psm1
if (-Not [string]::IsNullOrEmpty($KubeVersion) -and $platform -NE "eks") {
    PrepareKubernetes
}

Write-Host "Setup Calico for Windows..."
Set-ConfigParameters -var 'CALICO_DATASTORE_TYPE' -value $Datastore
Set-ConfigParameters -var 'ETCD_ENDPOINTS' -value $EtcdEndpoints

if (-Not [string]::IsNullOrEmpty($EtcdTlsSecretName)) {
    $calicoNs = GetCalicoNamespace
    SetupEtcdTlsFiles -SecretName "$EtcdTlsSecretName" -CalicoNamespace $calicoNs
}
Set-ConfigParameters -var 'ETCD_KEY_FILE' -value $EtcdKey
Set-ConfigParameters -var 'ETCD_CERT_FILE' -value $EtcdCert
Set-ConfigParameters -var 'ETCD_CA_CERT_FILE' -value $EtcdCaCert
Set-ConfigParameters -var 'K8S_SERVICE_CIDR' -value $ServiceCidr
Set-ConfigParameters -var 'DNS_NAME_SERVERS' -value $DNSServerIPs

if ($platform -EQ "aks") {
    Write-Host "Setup Calico for Windows for AKS..."
    $Backend="none"
    Set-ConfigParameters -var 'CALICO_NETWORKING_BACKEND' -value "none"
    Set-ConfigParameters -var 'KUBE_NETWORK' -value "azure.*"

    $calicoNs = "calico-system"
    GetCalicoKubeConfig -CalicoNamespace $calicoNs

    SetAKSCalicoStaticRules
}
if ($platform -EQ "eks") {
    EnableWinDsrForEKS

    $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "300"} -Method PUT -Uri http://169.254.169.254/latest/api/token -ErrorAction Ignore
    $awsNodeName = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri http://169.254.169.254/latest/meta-data/local-hostname -ErrorAction Ignore
    Write-Host "Setup Calico for Windows for EKS, node name $awsNodeName ..."
    $Backend = "none"

    Set-ConfigParameters -var 'NODENAME' -value $awsNodeName
    Set-ConfigParameters -var 'CALICO_NETWORKING_BACKEND' -value "none"
    Set-ConfigParameters -var 'KUBE_NETWORK' -value "vpc.*"

    $calicoNs = GetCalicoNamespace -KubeConfigPath C:\ProgramData\kubernetes\kubeconfig
    GetCalicoKubeConfig -CalicoNamespace $calicoNs -KubeConfigPath C:\ProgramData\kubernetes\kubeconfig
}
if ($platform -EQ "ec2") {
    $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "300"} -Method PUT -Uri http://169.254.169.254/latest/api/token -ErrorAction Ignore
    $awsNodeName = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri http://169.254.169.254/latest/meta-data/local-hostname -ErrorAction Ignore
    Write-Host "Setup Calico for Windows for AWS, node name $awsNodeName ..."
    Set-ConfigParameters -var 'NODENAME' -value $awsNodeName

    $calicoNs = GetCalicoNamespace
    GetCalicoKubeConfig -CalicoNamespace $calicoNs
    $Backend = GetBackendType -CalicoNamespace $calicoNs

    Write-Host "Backend networking is $Backend"
    if ($Backend -EQ "bgp") {
        Set-ConfigParameters -var 'CALICO_NETWORKING_BACKEND' -value "windows-bgp"
    }
}
if ($platform -EQ "gce") {
    $gceNodeName = Invoke-RestMethod -UseBasicParsing -Headers @{"Metadata-Flavor"="Google"} "http://metadata.google.internal/computeMetadata/v1/instance/hostname" -ErrorAction Ignore
    Write-Host "Setup Calico for Windows for GCE, node name $gceNodeName ..."
    $gceNodeNameQuote = """$gceNodeName"""
    Set-ConfigParameters -var 'NODENAME' -value $gceNodeNameQuote

    $calicoNs = GetCalicoNamespace
    GetCalicoKubeConfig -CalicoNamespace $calicoNs
    $Backend = GetBackendType -CalicoNamespace $calicoNs

    Write-Host "Backend networking is $Backend"
    if ($Backend -EQ "bgp") {
        Set-ConfigParameters -var 'CALICO_NETWORKING_BACKEND' -value "windows-bgp"
    }
}
if ($platform -EQ "bare-metal") {
    $calicoNs = GetCalicoNamespace
    GetCalicoKubeConfig -CalicoNamespace $calicoNs
    $Backend = GetBackendType -CalicoNamespace $calicoNs

    Write-Host "Backend networking is $Backend"
    if ($Backend -EQ "bgp") {
        Set-ConfigParameters -var 'CALICO_NETWORKING_BACKEND' -value "windows-bgp"
    }
}

if ($DownloadOnly -EQ "yes") {
    Write-Host "Downloaded Calico for Windows installation zip file."
    Exit
}

InstallCalico

if ($StartCalico -EQ "yes") {
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
}

if ($Backend -NE "none") {
    New-NetFirewallRule -Name KubectlExec10250 -Description "Enable kubectl exec and log" -Action Allow -LocalPort 10250 -Enabled True -DisplayName "kubectl exec 10250" -Protocol TCP -ErrorAction SilentlyContinue
}
