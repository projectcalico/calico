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

# We require the 64-bit version of Powershell, which should live at the following path.
$powerShellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$baseDir = "$PSScriptRoot\..\.."
$NSSMPath = "$baseDir\nssm-2.24\win64\nssm.exe"

function fileIsMissing($path)
{
    return (("$path" -EQ "") -OR (-NOT(Test-Path "$path")))
}

function Test-CalicoConfiguration()
{
    Write-Host "Validating configuration..."
    if (!$env:CNI_BIN_DIR)
    {
        throw "Config not loaded?."
    }
    if ($env:CALICO_NETWORKING_BACKEND -EQ "windows-bgp" -OR $env:CALICO_NETWORKING_BACKEND -EQ "vxlan") {
        if (fileIsMissing($env:CNI_BIN_DIR))
        {
            throw "CNI binary directory $env:CNI_BIN_DIR doesn't exist.  Please create it and ensure kubelet " +  `
                    "is configured with matching --cni-bin-dir."
        }
        if (fileIsMissing($env:CNI_CONF_DIR))
        {
            throw "CNI config directory $env:CNI_CONF_DIR doesn't exist.  Please create it and ensure kubelet " +  `
                    "is configured with matching --cni-conf-dir."
        }
    }
    if ($env:CALICO_NETWORKING_BACKEND -EQ "vxlan") {
        if (fileIsMissing($env:CNI_BIN_DIR))
        {
            throw "CNI binary directory $env:CNI_BIN_DIR doesn't exist.  Please create it and ensure kubelet " +  `
                    "is configured with matching --cni-bin-dir."
        }
        if (fileIsMissing($env:CNI_CONF_DIR))
        {
            throw "CNI config directory $env:CNI_CONF_DIR doesn't exist.  Please create it and ensure kubelet " +  `
                    "is configured with matching --cni-conf-dir."
        }
    }
    if ($env:CALICO_NETWORKING_BACKEND -EQ "vxlan" -AND $env:CNI_IPAM_TYPE -NE "calico-ipam") {
        throw "Calico VXLAN requires IPAM type calico-ipam, not $env:CNI_IPAM_TYPE."
    }
    if ($env:CALICO_DATASTORE_TYPE -EQ "kubernetes")
    {
        if (fileIsMissing($env:KUBECONFIG))
        {
            throw "kubeconfig file $env:KUBECONFIG doesn't exist.  Please update the configuration to match. " +  `
                    "the location of your kubeconfig file."
        }
    }
    elseif ($env:CALICO_DATASTORE_TYPE -EQ "etcdv3")
    {
        if (("$env:ETCD_ENDPOINTS" -EQ "") -OR ("$env:ETCD_ENDPOINTS" -EQ "<your etcd endpoints>"))
        {
            throw "Etcd endpoint not set, please update the configuration."
        }
        if (("$env:ETCD_KEY_FILE" -NE "") -OR ("$env:ETCD_CERT_FILE" -NE "") -OR ("$env:ETCD_CA_CERT_FILE" -NE ""))
        {
            if (fileIsMissing($env:ETCD_KEY_FILE))
            {
                throw "Some etcd TLS parameters are configured but etcd key file was not found."
            }
            if (fileIsMissing($env:ETCD_CERT_FILE))
            {
                throw "Some etcd TLS parameters are configured but etcd certificate file was not found."
            }
            if (fileIsMissing($env:ETCD_CA_CERT_FILE))
            {
                throw "Some etcd TLS parameters are configured but etcd CA certificate file was not found."
            }
        }
    }
    else
    {
        throw "Please set datastore type to 'etcdv3' or 'kubernetes'; current value: $env:CALICO_DATASTORE_TYPE."
    }
}

function Set-EnvVarIfNotSet {
    param(
        [parameter(Mandatory=$true)] $var,
        [parameter(Mandatory=$true)] $defaultValue
    )
    if (-not (Test-Path "env:$var"))
    {
        Write-Host "Environment variable $var is not set, setting it to the default value $defaultValue"
        [Environment]::SetEnvironmentVariable($var, $defaultValue, 'Process')
    }
}

function Set-ConfigParameters {
    param(
        [parameter(Mandatory=$true)] $var,
        [parameter(Mandatory=$true)] $value
    )
    $OldString='Set-EnvVarIfNotSet -var "{0}".*$' -f $var
    $NewString='Set-EnvVarIfNotSet -var "{0}" -defaultValue "{1}"' -f $var, $value
    (Get-Content $baseDir\config.ps1) -replace $OldString, $NewString | Set-Content $baseDir\config.ps1 -Force
}

function Install-CNIPlugin()
{
    Write-Host "Copying CNI binaries to $env:CNI_BIN_DIR"
    cp "$baseDir\cni\*.exe" "$env:CNI_BIN_DIR"

    $cniConfFile = $env:CNI_CONF_DIR + "\" + $env:CNI_CONF_FILENAME
    Write-Host "Writing CNI configuration to $cniConfFile."
    $nodeNameFile = "$baseDir\nodename".replace('\', '\\')
    $etcdKeyFile = "$env:ETCD_KEY_FILE".replace('\', '\\')
    $etcdCertFile = "$env:ETCD_CERT_FILE".replace('\', '\\')
    $etcdCACertFile = "$env:ETCD_CA_CERT_FILE".replace('\', '\\')
    $kubeconfigFile = "$env:KUBECONFIG".replace('\', '\\')
    $mode = ""
    if ($env:CALICO_NETWORKING_BACKEND -EQ "vxlan") {
        $mode = "vxlan"
    }

    $dnsIPs = "$env:DNS_NAME_SERVERS".Split(",")
    $ipList = @()
    foreach ($ip in $dnsIPs) {
        $ipList += "`"$ip`""
    }
    $dnsIPList=($ipList -join ",").TrimEnd(',')

    # HNS v1 and v2 have different string values for the ROUTE endpoint policy type.
    $routeType = "ROUTE"
    if (Get-IsContainerdRunning)
    {
        $routeType = "SDNROUTE"
    }

    $dsrSupport = "false"
    if (Get-IsDSRSupported)
    {
        $dsrSupport = "true"
    }

    (Get-Content "$baseDir\cni.conf.template") | ForEach-Object {
        $_.replace('__NODENAME_FILE__', $nodeNameFile).
                replace('__KUBECONFIG__', $kubeconfigFile).
                replace('__K8S_SERVICE_CIDR__', $env:K8S_SERVICE_CIDR).
                replace('__DNS_NAME_SERVERS__', $dnsIPList).
                replace('__DATASTORE_TYPE__', $env:CALICO_DATASTORE_TYPE).
                replace('__DSR_SUPPORT__', $dsrSupport).
                replace('__ETCD_ENDPOINTS__', $env:ETCD_ENDPOINTS).
                replace('__ETCD_KEY_FILE__', $etcdKeyFile).
                replace('__ETCD_CERT_FILE__', $etcdCertFile).
                replace('__ETCD_CA_CERT_FILE__', $etcdCACertFile).
                replace('__IPAM_TYPE__', $env:CNI_IPAM_TYPE).
                replace('__MODE__', $mode).
                replace('__VNI__', $env:VXLAN_VNI).
                replace('__MAC_PREFIX__', $env:VXLAN_MAC_PREFIX).
                replace('__ROUTE_TYPE__', $routeType)
    } | Set-Content "$cniConfFile"
    Write-Host "Wrote CNI configuration."
}

function Remove-CNIPlugin()
{
    $cniConfFile = $env:CNI_CONF_DIR + "\" + $env:CNI_CONF_FILENAME
    Write-Host "Removing $cniConfFile and Calico binaries."
    rm $cniConfFile
    rm "$env:CNI_BIN_DIR/calico*.exe"
}

function Install-NodeService()
{
    Write-Host "Installing node startup service..."

    ensureRegistryKey

    # Ensure our service file can run.
    Unblock-File $baseDir\node\node-service.ps1

    & $NSSMPath install CalicoNode $powerShellPath
    & $NSSMPath set CalicoNode AppParameters $baseDir\node\node-service.ps1
    & $NSSMPath set CalicoNode AppDirectory $baseDir
    & $NSSMPath set CalicoNode DisplayName "Calico Windows Startup"
    & $NSSMPath set CalicoNode Description "Calico Windows Startup, configures Calico datamodel resources for this node."

    # Configure it to auto-start by default.
    & $NSSMPath set CalicoNode Start SERVICE_AUTO_START
    & $NSSMPath set CalicoNode ObjectName LocalSystem
    & $NSSMPath set CalicoNode Type SERVICE_WIN32_OWN_PROCESS

    # Throttle process restarts if Felix restarts in under 1500ms.
    & $NSSMPath set CalicoNode AppThrottle 1500

    # Create the log directory if needed.
    if (-Not(Test-Path "$env:CALICO_LOG_DIR"))
    {
        write "Creating log directory."
        md -Path "$env:CALICO_LOG_DIR"
    }
    & $NSSMPath set CalicoNode AppStdout $env:CALICO_LOG_DIR\calico-node.log
    & $NSSMPath set CalicoNode AppStderr $env:CALICO_LOG_DIR\calico-node.err.log

    # Configure online file rotation.
    & $NSSMPath set CalicoNode AppRotateFiles 1
    & $NSSMPath set CalicoNode AppRotateOnline 1
    # Rotate once per day.
    & $NSSMPath set CalicoNode AppRotateSeconds 86400
    # Rotate after 10MB.
    & $NSSMPath set CalicoNode AppRotateBytes 10485760

    Write-Host "Done installing startup service."
}

function Remove-NodeService()
{
    & $NSSMPath remove CalicoNode confirm
}

function Install-FelixService()
{
    Write-Host "Installing Felix service..."

    # Ensure our service file can run.
    Unblock-File $baseDir\felix\felix-service.ps1

    # We run Felix via a wrapper script to make it easier to update env vars.
    & $NSSMPath install CalicoFelix $powerShellPath
    & $NSSMPath set CalicoFelix AppParameters $baseDir\felix\felix-service.ps1
    & $NSSMPath set CalicoFelix AppDirectory $baseDir
    & $NSSMPath set CalicoFelix DependOnService "CalicoNode"
    & $NSSMPath set CalicoFelix DisplayName "Calico Windows Agent"
    & $NSSMPath set CalicoFelix Description "Calico Windows Per-host Agent, Felix, provides network policy enforcement for Kubernetes."

    # Configure it to auto-start by default.
    & $NSSMPath set CalicoFelix Start SERVICE_AUTO_START
    & $NSSMPath set CalicoFelix ObjectName LocalSystem
    & $NSSMPath set CalicoFelix Type SERVICE_WIN32_OWN_PROCESS

    # Throttle process restarts if Felix restarts in under 1500ms.
    & $NSSMPath set CalicoFelix AppThrottle 1500

    # Create the log directory if needed.
    if (-Not(Test-Path "$env:CALICO_LOG_DIR"))
    {
        write "Creating log directory."
        md -Path "$env:CALICO_LOG_DIR"
    }
    & $NSSMPath set CalicoFelix AppStdout $env:CALICO_LOG_DIR\calico-felix.log
    & $NSSMPath set CalicoFelix AppStderr $env:CALICO_LOG_DIR\calico-felix.err.log

    # Configure online file rotation.
    & $NSSMPath set CalicoFelix AppRotateFiles 1
    & $NSSMPath set CalicoFelix AppRotateOnline 1
    # Rotate once per day.
    & $NSSMPath set CalicoFelix AppRotateSeconds 86400
    # Rotate after 10MB.
    & $NSSMPath set CalicoFelix AppRotateBytes 10485760

    Write-Host "Done installing Felix service."
}

function Remove-FelixService() {
    & $NSSMPath remove CalicoFelix confirm
}

function Install-ConfdService()
{
    Write-Host "Installing confd service..."

    # Ensure our service file can run.
    Unblock-File $baseDir\confd\confd-service.ps1

    # We run confd via a wrapper script to make it easier to update env vars.
    & $NSSMPath install CalicoConfd $powerShellPath
    & $NSSMPath set CalicoConfd AppParameters $baseDir\confd\confd-service.ps1
    & $NSSMPath set CalicoConfd AppDirectory $baseDir
    & $NSSMPath set CalicoConfd DependOnService "CalicoNode"
    & $NSSMPath set CalicoConfd DisplayName "Calico BGP Agent"
    & $NSSMPath set CalicoConfd Description "Calico BGP Agent, confd, configures BGP routing."

    # Configure it to auto-start by default.
    & $NSSMPath set CalicoConfd Start SERVICE_AUTO_START
    & $NSSMPath set CalicoConfd ObjectName LocalSystem
    & $NSSMPath set CalicoConfd Type SERVICE_WIN32_OWN_PROCESS

    # Throttle process restarts if confd restarts in under 1500ms.
    & $NSSMPath set CalicoConfd AppThrottle 1500

    # Create the log directory if needed.
    if (-Not(Test-Path "$env:CALICO_LOG_DIR"))
    {
        write "Creating log directory."
        md -Path "$env:CALICO_LOG_DIR"
    }
    & $NSSMPath set CalicoConfd AppStdout $env:CALICO_LOG_DIR\calico-confd.log
    & $NSSMPath set CalicoConfd AppStderr $env:CALICO_LOG_DIR\calico-confd.err.log

    # Configure online file rotation.
    & $NSSMPath set CalicoConfd AppRotateFiles 1
    & $NSSMPath set CalicoConfd AppRotateOnline 1
    # Rotate once per day.
    & $NSSMPath set CalicoConfd AppRotateSeconds 86400
    # Rotate after 10MB.
    & $NSSMPath set CalicoConfd AppRotateBytes 10485760

    Write-Host "Done installing confd service."
}

function Remove-ConfdService() {
    & $NSSMPath remove CalicoConfd confirm
}

function Install-UpgradeService()
{
    Write-Host "Installing Calico Upgrade startup service..."

    ensureRegistryKey

    # Ensure our service file can run.
    Unblock-File $baseDir\upgrade\upgrade-service.ps1

    & $NSSMPath install CalicoUpgrade $powerShellPath
    & $NSSMPath set CalicoUpgrade AppParameters $baseDir\upgrade\upgrade-service.ps1
    & $NSSMPath set CalicoUpgrade AppDirectory $baseDir
    & $NSSMPath set CalicoUpgrade DisplayName "Calico Windows Upgrade"
    & $NSSMPath set CalicoUpgrade Description "Calico Windows Upgrade monitors and manages upgrades"

    # Configure it to auto-start by default.
    & $NSSMPath set CalicoUpgrade Start SERVICE_AUTO_START
    & $NSSMPath set CalicoUpgrade ObjectName LocalSystem
    & $NSSMPath set CalicoUpgrade Type SERVICE_WIN32_OWN_PROCESS

    # Throttle process restarts if Felix restarts in under 1500ms.
    & $NSSMPath set CalicoUpgrade AppThrottle 1500

    # Create the log directory if needed.
    if (-Not(Test-Path "$env:CALICO_LOG_DIR"))
    {
        write "Creating log directory."
        md -Path "$env:CALICO_LOG_DIR"
    }
    & $NSSMPath set CalicoUpgrade AppStdout $env:CALICO_LOG_DIR\calico-upgrade.log
    & $NSSMPath set CalicoUpgrade AppStderr $env:CALICO_LOG_DIR\calico-upgrade.err.log

    # Configure online file rotation.
    & $NSSMPath set CalicoUpgrade AppRotateFiles 1
    & $NSSMPath set CalicoUpgrade AppRotateOnline 1
    # Rotate once per day.
    & $NSSMPath set CalicoUpgrade AppRotateSeconds 86400
    # Rotate after 10MB.
    & $NSSMPath set CalicoUpgrade AppRotateBytes 10485760

    Write-Host "Done installing upgrade service."
}

function Remove-UpgradeService()
{
    $svc = Get-Service | where Name -EQ 'CalicoUpgrade'
    if ($svc -NE $null)
    {
        if ($svc.Status -EQ 'Running')
        {
            Write-Host "CalicoUpgrade service is running, stopping it..."
            & $NSSMPath stop CalicoUpgrade confirm
        }
        Write-Host "Removing CalicoUpgrade service..."
        & $NSSMPath remove CalicoUpgrade confirm
    }
}

function Wait-ForManagementIP($NetworkName)
{
    while ((Get-HnsNetwork | ? Name -EQ $NetworkName).ManagementIP -EQ $null)
    {
        Write-Host "Waiting for management IP to appear on network $NetworkName..."
        Start-Sleep 1
    }
    return (Get-HnsNetwork | ? Name -EQ $NetworkName).ManagementIP
}

function Get-LastBootTime()
{
    $bootTime = (Get-CimInstance win32_operatingsystem | select @{LABEL='LastBootUpTime';EXPRESSION={$_.lastbootuptime}}).LastBootUpTime
    if (($bootTime -EQ $null) -OR ($bootTime.length -EQ 0))
    {
        throw "Failed to get last boot time"
    }
 
    # This function is used in conjunction with Get-StoredLastBootTime, which
    # returns a string, so convert the datetime value to a string using the "general" standard format.
    return $bootTime.ToString("G")
}

$softwareRegistryKey = "HKLM:\Software\Tigera"
$calicoRegistryKey = $softwareRegistryKey + "\Calico"

function ensureRegistryKey()
{
    if (! (Test-Path $softwareRegistryKey))
    {
        New-Item $softwareRegistryKey
    }
    if (! (Test-Path $calicoRegistryKey))
    {
        New-Item $calicoRegistryKey
    }
}

function Get-StoredLastBootTime()
{
    try
    {
        return (Get-ItemProperty $calicoRegistryKey -ErrorAction Ignore).LastBootTime
    }
    catch
    {
        $PSItem.Exception.Message
    }
}

function Set-StoredLastBootTime($lastBootTime)
{
    ensureRegistryKey

    return Set-ItemProperty $calicoRegistryKey -Name LastBootTime -Value $lastBootTime
}

function Wait-ForCalicoInit()
{
    Write-Host "Waiting for Calico initialisation to finish..."
    $Stored=Get-StoredLastBootTime
    $Current=Get-LastBootTime
    while ($Stored -NE $Current) {
        Write-Host "Waiting for Calico initialisation to finish...StoredLastBootTime $Stored, CurrentLastBootTime $Current"
        Start-Sleep 1

        $Stored=Get-StoredLastBootTime
        $Current=Get-LastBootTime
    }
    Write-Host "Calico initialisation finished."
}

function Get-PlatformType()
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
        $awsNodeName=Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/local-hostname -ErrorAction Ignore
    } Catch {
        $restError = $_
    }
    if ($restError -eq $null) {
        return ("ec2")
    }
    
    # GCE
    $restError = $null
    Try {
        $gceNodeName = Invoke-RestMethod -UseBasicParsing -Headers @{"Metadata-Flavor"="Google"} "http://metadata.google.internal/computeMetadata/v1/instance/hostname"
    } Catch {
        $restError = $_
    }
    if ($restError -eq $null) {
        return ("gce")
    }

    return ("bare-metal")
}

function Set-MetaDataServerRoute($mgmtIP)
{
    $route = $null
    Try {
        $route=Get-NetRoute -DestinationPrefix 169.254.169.254/32 2>$null
    } Catch {
        Write-Host "Metadata server route not found."
    }
    if ($route -eq $null) {
        Write-Host "Restore metadata server route."
    
        $routePrefix= $mgmtIP + "/32"
        Try {
            $ifIndex=Get-NetRoute -DestinationPrefix $routePrefix | Select-Object -ExpandProperty ifIndex
            New-NetRoute -DestinationPrefix 169.254.169.254/32 -InterfaceIndex $ifIndex
        } Catch {
            Write-Host "Warning! Failed to restore metadata server route."
        }
    }
}

function Get-UpgradeService()
{
    # Don't use get-wmiobject since that is not available in Powershell 7.
    return Get-CimInstance -Query "SELECT * from Win32_Service WHERE name = 'CalicoUpgrade'"
}

# Assume same relative path for containerd CNI bin/conf dir
# By default, containerd is installed in c:\Program Files\containerd, and CNI bin/conf is in
# c:\Program Files\containerd\cni\bin and c:\Program Files\containerd\cni\conf.
function Get-ContainerdCniBinDir()
{
    $path = getContainerdPath
    return "$path\cni\bin"
}
function Get-ContainerdCniConfDir()
{
    $path = getContainerdPath
    return "$path\cni\conf"
}

function getContainerdService()
{
    # Don't use get-wmiobject since that is not available in Powershell 7.
    return Get-CimInstance -Query "SELECT * from Win32_Service WHERE name = 'containerd'"
}

function getContainerdPath()
{
    # Get the containerd service pathname.
    $containerdPathName = getContainerdService | Select-Object -ExpandProperty PathName

    # Get the path only, and remove any extra quotes left over.
    return (Split-Path -Path $containerdPathname) -replace '"', ""
}

function Get-IsContainerdRunning()
{
    return (getContainerdService | Select-Object -ExpandProperty State) -EQ "Running"
}

function Get-IsDSRSupported()
{
    # Determine the windows version and build number for DSR support.
    # OsHardwareAbstractionLayer is a version string like 10.0.17763.1432
    $OSInfo = (Get-ComputerInfo  | select WindowsVersion, OsBuildNumber, OsHardwareAbstractionLayer)

    # Windows supports DSR if
    # - it is 1809 build 1432
    # - it is 1903 or later
    $min1809BuildSupportingDSR = (($OSInfo.OsHardwareAbstractionLayer.Split(".") | select-object -Last 1) -as [int]) -GE 1432
    $windows1809 = (($OSInfo.WindowsVersion -as [int]) -EQ 1809 -And ($OSInfo.OsBuildNumber -as [int]) -GE 17763)
    $windows1903OrNewer = (($OSInfo.WindowsVersion -as [int]) -GE 1903 -And ($OSInfo.OsBuildNumber -as [int]) -GE 18317)

    return ($windows1809 -And $min1809BuildSupportingDSR) -Or $windows1903OrNewer
}

Export-ModuleMember -Function 'Test-*'
Export-ModuleMember -Function 'Install-*'
Export-ModuleMember -Function 'Remove-*'
Export-ModuleMember -Function 'Wait-*'
Export-ModuleMember -Function 'Get-*'
Export-ModuleMember -Function 'Set-*'
