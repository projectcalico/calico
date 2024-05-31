# This script is adapated from https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-ContainerdRuntime/install-containerd-runtime.ps1
# Reference: https://learn.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=containerd


############################################################
# Script to set up a VM instance to run with containerd and nerdctl
############################################################

<#
    .NOTES
        Copyright (c) Microsoft Corporation.  All rights reserved.

        Use of this sample source code is subject to the terms of the Microsoft
        license agreement under which you licensed this sample source code. If
        you did not accept the terms of the license agreement, you are not
        authorized to use this sample source code. For the terms of the license,
        please see the license agreement between you and Microsoft or, if applicable,
        see the LICENSE.RTF on your install media or the root of your tools installation.
        THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.

    .SYNOPSIS
        Installs the prerequisites for creating Windows containers

    .DESCRIPTION
        Installs the prerequisites for creating Windows containers

    .PARAMETER ContainerDVersion
        Version of containerd to use

    .PARAMETER NerdCTLVersion
        Version of nerdctl to use

    .PARAMETER WinCNIVersion

    .PARAMETER ExternalNetAdapter
        Specify a specific network adapter to bind to a DHCP network

    .PARAMETER Force 
        If a restart is required, forces an immediate restart.
        
    .PARAMETER HyperV 
        If passed, prepare the machine for Hyper-V containers

    .PARAMETER NoRestart
        If a restart is required the script will terminate and will not reboot the machine

    .PARAMETER ContainerBaseImage
        Use this to specifiy the URI of the container base image you wish to pull

    .PARAMETER TransparentNetwork
        If passed, use DHCP configuration. (alias -UseDHCP)

    .EXAMPLE
        .\install-containerd-runtime.ps1

#>
#Requires -Version 5.0

[CmdletBinding(DefaultParameterSetName="Standard")]
param(
    [string]
    [ValidateNotNullOrEmpty()]
    $ContainerDVersion = "1.6.6",

    [string]
    [ValidateNotNullOrEmpty()]
    $NerdCTLVersion = "0.21.0",

    [string]
    [ValidateNotNullOrEmpty()]
    $WinCNIVersion = "0.3.0",

    [string]
    $ExternalNetAdapter,

    [switch]
    $Force,

    [switch]
    $HyperV,

    [switch]
    $NoRestart,

    [Parameter(DontShow)]
    [switch]
    $PSDirect,

    [string]
    $ContainerBaseImage,

    [Parameter(ParameterSetName="Staging", Mandatory)]
    [switch]
    $Staging,

    [switch]
    [alias("UseDHCP")]
    $TransparentNetwork
)

$global:RebootRequired = $false

$global:ErrorFile = "$pwd\install-container-runtime.err"

$global:BootstrapTask = "ContainerBootstrap"

$global:HyperVImage = "NanoServer"

function
Restart-And-Run()
{
    Test-Admin

    Write-Output "Restart is required; restarting now..."

    $argList = $script:MyInvocation.Line.replace($script:MyInvocation.InvocationName, "")

    #
    # Update .\ to the invocation directory for the bootstrap
    #
    $scriptPath = $script:MyInvocation.MyCommand.Path

    $argList = $argList -replace "\.\\", "$pwd\"

    if ((Split-Path -Parent -Path $scriptPath) -ne $pwd)
    {
        $sourceScriptPath = $scriptPath
        $scriptPath = "$pwd\$($script:MyInvocation.MyCommand.Name)"

        Copy-Item $sourceScriptPath $scriptPath
    }

    Write-Output "Creating scheduled task action ($scriptPath $argList)..."
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoExit $scriptPath $argList"

    Write-Output "Creating scheduled task trigger..."
    $trigger = New-ScheduledTaskTrigger -AtLogOn

    Write-Output "Registering script to re-run at next user logon..."
    Register-ScheduledTask -TaskName $global:BootstrapTask -Action $action -Trigger $trigger -RunLevel Highest | Out-Null

    try
    {
        if ($Force)
        {
            Restart-Computer -Force
        }
        else
        {
            Restart-Computer
        }
    }
    catch
    {
        Write-Error $_

        Write-Output "Please restart your computer manually to continue script execution."
    }

    exit
}


function
Install-Feature
{
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]
        $FeatureName
    )

    Write-Output "Querying status of Windows feature: $FeatureName..."
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)
    {
        if ((Get-WindowsFeature $FeatureName).Installed)
        {
            Write-Output "Feature $FeatureName is already enabled."
        }
        else
        {
            Test-Admin

            Write-Output "Enabling feature $FeatureName..."
        }

        $featureInstall = Add-WindowsFeature $FeatureName

        if ($featureInstall.RestartNeeded -eq "Yes")
        {
            $global:RebootRequired = $true;
        }
    }
    else
    {
        if ((Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).State -eq "Disabled")
        {
            if (Test-Nano)
            {
                throw "This NanoServer deployment does not include $FeatureName.  Please add the appropriate package"
            }

            Test-Admin

            Write-Output "Enabling feature $FeatureName..."
            $feature = Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart

            if ($feature.RestartNeeded -eq "True")
            {
                $global:RebootRequired = $true;
            }
        }
        else
        {
            Write-Output "Feature $FeatureName is already enabled."

            if (Test-Nano)
            {
                #
                # Get-WindowsEdition is not present on Nano.  On Nano, we assume reboot is not needed
                #
            }
            elseif ((Get-WindowsEdition -Online).RestartNeeded)
            {
                $global:RebootRequired = $true;
            }
        }
    }
}


function
New-ContainerTransparentNetwork
{
    # Check if we've already created the container network
    $networks = Get-HNSNetwork | Where-Object { $_.Name -eq "Transparent" }
    if ($networks -ne $null)
    {
        Write-Output "Container network (Transparent) already exists. Skipping network creation".
        return;
    }

    # Continue to create container network
    if ($ExternalNetAdapter)
    {
        $netAdapter = (Get-NetAdapter | Where-Object {$_.Name -eq "$ExternalNetAdapter"})[0]
    }
    else
    {
        $netAdapter = (Get-NetAdapter |Where-Object {($_.Status -eq 'Up') -and ($_.ConnectorPresent)})[0]
    }

    Write-Output "Creating container network (Transparent)..."
    
    # Download and Install powershell module HNS-Network
    $containerdPath='C:\Program Files\containerd\cni\bin\'
    if (-not (Test-Path $containerdPath)){
        curl.exe -LO https://github.com/microsoft/windows-container-networking/releases/download/v0.3.0/windows-container-networking-cni-amd64-v0.3.0.zip
        Expand-Archive -Path .\windows-container-networking-cni-amd64-v0.3.0.zip -DestinationPath $containerdPath
    }
    curl.exe -LO https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/hns.psm1
    Import-Module -Force ./hns.psm1

    # Create Transparent network
    New-HNSNetwork -Type Transparent -Name "Transparent" -AdapterName $netAdapter.Name | Out-Null
}


function
Install-ContainerDHost
{
    "If this file exists when Install-ContainerDHost.ps1 exits, the script failed!" | Out-File -FilePath $global:ErrorFile

    if (Test-Client)
    {
        if (-not $HyperV)
        {
            Write-Output "Enabling Hyper-V containers by default for Client SKU"
            $HyperV = $true
        }    
    }
    #
    # Validate required Windows features
    #
    Install-Feature -FeatureName Containers

    if ($HyperV)
    {
        Install-Feature -FeatureName Hyper-V
    }

    if ($global:RebootRequired)
    {
        if ($NoRestart)
        {
            Write-Warning "A reboot is required; stopping script execution"
            exit
        }

        Restart-And-Run
    }

    #
    # Unregister the bootstrap task, if it was previously created
    #
    if ($null -ne (Get-ScheduledTask -TaskName $global:BootstrapTask -ErrorAction SilentlyContinue))
    {
        Unregister-ScheduledTask -TaskName $global:BootstrapTask -Confirm:$false
    }

    #
    # Configure networking
    #
    if ($($PSCmdlet.ParameterSetName) -ne "Staging")
    {
        if ($TransparentNetwork)
        {
            Write-Output "Waiting for Hyper-V Management..."
            $networks = $null

            try
            {
                $networks = Get-ContainerNetwork -ErrorAction SilentlyContinue
            }
            catch
            {
                #
                # If we can't query network, we are in bootstrap mode.  Assume no networks
                #
            }

            if ($networks.Count -eq 0)
            {
                Write-Output "Enabling container networking..."
                New-ContainerTransparentNetwork
            }
            else
            {
                Write-Output "Networking is already configured.  Confirming configuration..."
                
                $transparentNetwork = $networks |Where-Object { $_.Mode -eq "Transparent" }

                if ($null -eq $transparentNetwork)
                {
                    Write-Output "We didn't find a configured external network; configuring now..."
                    New-ContainerTransparentNetwork
                }
                else
                {
                    if ($ExternalNetAdapter)
                    {
                        $netAdapters = (Get-NetAdapter | Where-Object {$_.Name -eq "$ExternalNetAdapter"})

                        if ($netAdapters.Count -eq 0)
                        {
                            throw "No adapters found that match the name $ExternalNetAdapter"
                        }

                        $netAdapter = $netAdapters[0]
                        $transparentNetwork = $networks | Where-Object { $_.NetworkAdapterName -eq $netAdapter.InterfaceDescription }

                        if ($null-eq $transparentNetwork)
                        {
                            throw "One or more external networks are configured, but not on the requested adapter ($ExternalNetAdapter)"
                        }

                        Write-Output "Configured transparent network found: $($transparentNetwork.Name)"
                    }
                    else
                    {
                        Write-Output "Configured transparent network found: $($transparentNetwork.Name)"
                    }
                }
            }
        }
    }

    #
    # Install, register, and start Containerd
    #
    if (Test-Containerd)
    {
        Write-Output "Containerd is already installed."
    }
    else
    {
        Install-Containerd -ContainerDVersion $ContainerDVersion -NerdCTLVersion $NerdCTLVersion -ContainerBaseImage $ContainerBaseImage
    }

    Remove-Item $global:ErrorFile

    Write-Output "Script complete!"
}$global:AdminPriviledges = $false
$global:ContainerDDataPath = "$($env:ProgramFiles)\container"
$global:ContainerDServiceName = "containerd"

function
Copy-File
{
    [CmdletBinding()]
    param(
        [string]
        $SourcePath,
        
        [string]
        $DestinationPath
    )
    
    if ($SourcePath -eq $DestinationPath)
    {
        return
    }
          
    if (Test-Path $SourcePath)
    {
        Copy-Item -Path $SourcePath -Destination $DestinationPath
    }
    elseif ($null -ne ($SourcePath -as [System.URI]).AbsoluteURI)
    {
        if (Test-Nano)
        {
            $handler = New-Object System.Net.Http.HttpClientHandler
            $client = New-Object System.Net.Http.HttpClient($handler)
            $client.Timeout = New-Object System.TimeSpan(0, 30, 0)
            $cancelTokenSource = [System.Threading.CancellationTokenSource]::new() 
            $responseMsg = $client.GetAsync([System.Uri]::new($SourcePath), $cancelTokenSource.Token)
            $responseMsg.Wait()

            if (!$responseMsg.IsCanceled)
            {
                $response = $responseMsg.Result
                if ($response.IsSuccessStatusCode)
                {
                    $downloadedFileStream = [System.IO.FileStream]::new($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
                    $copyStreamOp = $response.Content.CopyToAsync($downloadedFileStream)
                    $copyStreamOp.Wait()
                    $downloadedFileStream.Close()
                    if ($null -ne $copyStreamOp.Exception)
                    {
                        throw $copyStreamOp.Exception
                    }      
                }
            }  
        }
        elseif ($PSVersionTable.PSVersion.Major -ge 5)
        {
            #
            # We disable progress display because it kills performance for large downloads (at least on 64-bit PowerShell)
            #
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $SourcePath -OutFile $DestinationPath -UseBasicParsing
            $ProgressPreference = 'Continue'
        }
        else
        {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($SourcePath, $DestinationPath)
        } 
    }
    else
    {
        throw "Cannot copy from $SourcePath"
    }
}


function 
Test-Admin()
{
    # Get the ID and security principal of the current user account
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
  
    # Get the security principal for the Administrator role
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
  
    # Check to see if we are currently running "as Administrator"
    if ($myWindowsPrincipal.IsInRole($adminRole))
    {
        $global:AdminPriviledges = $true
        return
    }
    else
    {
        #
        # We are not running "as Administrator"
        # Exit from the current, unelevated, process
        #
        throw "You must run this script as administrator"   
    }
}


function 
Test-Client()
{
    return (-not ((Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) -or (Test-Nano)))
}


function 
Test-Nano()
{
    $EditionId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID').EditionId

    return (($EditionId -eq "ServerStandardNano") -or 
            ($EditionId -eq "ServerDataCenterNano") -or 
            ($EditionId -eq "NanoServer") -or 
            ($EditionId -eq "ServerTuva"))
}


function 
Wait-Network()
{
    $connectedAdapter = Get-NetAdapter | Where-Object ConnectorPresent

    if ($null -eq $connectedAdapter)
    {
        throw "No connected network"
    }
       
    $startTime = Get-Date
    $timeElapsed = $(Get-Date) - $startTime

    while ($($timeElapsed).TotalMinutes -lt 5)
    {
        $readyNetAdapter = $connectedAdapter | Where-Object Status -eq 'Up'

        if ($null -ne $readyNetAdapter)
        {
            return;
        }

        Write-Output "Waiting for network connectivity..."
        Start-Sleep -sec 5

        $timeElapsed = $(Get-Date) - $startTime
    }

    throw "Network not connected after 5 minutes"
}


function 
Install-Containerd()
{
    [CmdletBinding()]
    param(
        [string]
        [ValidateNotNullOrEmpty()]
        $ContainerdVersion = "1.6.6",

        [string]
        [ValidateNotNullOrEmpty()]
        $NerdCTLVersion = "0.21.0",

        [string]
        [ValidateNotNullOrEmpty()]
        $WinCNIVersion = "0.3.0",

        [string]
        $ContainerBaseImage
    )

    Test-Admin

    Write-Output "Downloading containerd, nerdCTL, and Windows CNI binaries..."

    $ContainerdPath = "$Env:ProgramFiles\containerd"
    $NerdCTLPath = "$Env:ProgramFiles\nerdctl"
    $WinCNIPath = "$ContainerdPath\cni\bin"

    # Download and extract desired containerd Windows binaries
    if (!(Test-Path $ContainerdPath)) { mkdir -Force -Path $ContainerdPath | Out-Null }
    if (!(Test-Path $NerdCTLPath)) { mkdir -Force -Path $NerdCTLPath | Out-Null }
    if (!(Test-Path $WinCNIPath)) { mkdir -Force -Path $WinCNIPath | Out-Null }

    $ContainerdZip = "containerd-$ContainerDVersion-windows-amd64.tar.gz"
    Copy-File "https://github.com/containerd/containerd/releases/download/v$ContainerDVersion/$ContainerdZip" "$ContainerdPath\$ContainerdZip"
    tar.exe -xvf "$ContainerdPath\$ContainerdZip" -C $ContainerdPath
    Write-Output "Containerd binaries added to $ContainerdPath"

    #Download and extract nerdctl binaries
    $NerdCTLZip = "nerdctl-$NerdCTLVersion-windows-amd64.tar.gz"
    Copy-File "https://github.com/containerd/nerdctl/releases/download/v$NerdCTLVersion/$NerdCTLZip" "$NerdCTLPath\$NerdCTLZip"
    tar.exe -xvf "$NerdCTLPath\$NerdCTLZip" -C $NerdCTLPath
    Write-Output "NerdCTL binary added to $NerdCTLPath"

    #Download and extract win cni binaries
    $WinCNIZip = "windows-container-networking-cni-amd64-v$WinCNIVersion.zip"
    Copy-File "https://github.com/microsoft/windows-container-networking/releases/download/v$WinCNIVersion/$WinCNIZip" "$WinCNIPath\$WinCNIZip"
    tar.exe -xvf "$WinCNIPath\$WinCNIZip" -C $WinCNIPath
    Write-Output "CNI plugin binaries added to $WinCNIPath"

    Write-Output "Adding $ContainerdPath, $NerdCTLPath, $WinCNIPath to the path"

    $NewPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name path).path
    if($NewPath.contains("containerd")) {
        Write-Output "$ContainerdPath already in PATH"
    } else {
        $NewPath = "$NewPath;$ContainerdPath\bin;"
    }

    if($NewPath.contains("nerdctl")) {
        Write-Output "$NerdCTLPath already in PATH"
    } else {
        $NewPath = "$NewPath;$NerdCTLPath;"
    }

    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $NewPath
    $env:Path = $NewPath


    Write-Output "Configuring the containerd service"

    #Configure containerd service
    containerd.exe config default | Out-File $ContainerdPath\config.toml -Encoding ascii

    # Review the configuration. Depending on setup you may want to adjust:
    # - the sandbox_image (Kubernetes pause image)
    # - cni bin_dir and conf_dir locations
    Get-Content $ContainerdPath\config.toml

    # Register and start service
    containerd.exe --register-service

    Start-Containerd

    #
    # Waiting for containerd to come to steady state
    #
    Wait-Containerd

    if(-not [string]::IsNullOrEmpty($ContainerBaseImage)) {
        Write-Output "Attempting to pull specified base image: $ContainerBaseImage"
        nerdctl pull $ContainerBaseImage
    }

    Write-Output "The following images are present on this machine:"
    
    nerdctl images -a | Write-Output
}

function 
Start-Containerd()
{
    Start-Service -Name $global:ContainerdServiceName
}


function 
Stop-Containerd()
{
    Stop-Service -Name $global:ContainerdServiceName
}

function
Remove-Containerd() 
{
    Stop-Containerd
    (Get-WmiObject -Class Win32_Service -Filter "Name='containerd'").delete()
    Remove-Item -r -Force "$Env:ProgramFiles\containerd"
    Remove-Item -r -Force "$Env:ProgramFiles\nerdctl"
}

function 
Test-Containerd()
{
    $service = Get-Service -Name $global:ContainerdServiceName -ErrorAction SilentlyContinue

    return ($null -ne $service)
}


function 
Wait-Containerd()
{
    Write-Output "Waiting for Containerd daemon..."
    $containerdReady = $false
    $startTime = Get-Date

    while (-not $containerdReady)
    {
        try
        {
            nerdctl version | Out-Null

            if (-not $?)
            {
                throw "Containerd daemon is not running yet"
            }

            $containerdReady = $true
        }
        catch 
        {
            $timeElapsed = $(Get-Date) - $startTime

            if ($($timeElapsed).TotalMinutes -ge 1)
            {
                throw "Containerd Daemon did not start successfully within 1 minute."
            } 

            # Swallow error and try again
            Start-Sleep -sec 1
        }
    }
    Write-Output "Successfully connected to Containerd Daemon."
}

# Added by Tigera
$ProgressPreference = "SilentlyContinue"

try
{
    Install-ContainerDHost

    # containerd expects to be in c:\Program Files
    mkdir -p C:\bin
    Copy-Item "$Env:ProgramFiles\containerd\bin\ctr.exe" "c:\bin"
    C:\bin\ctr.exe --version

    Write-Output "Pulling servercore:1809 image..."
    C:\bin\ctr.exe -n k8s.io images pull mcr.microsoft.com/windows/servercore:1809 | Out-Null

    Write-Output "Pulling pause image..."
    c:\bin\ctr.exe images pull k8s.gcr.io/pause:3.5 | Out-Null

    Write-Output "Accessing kube-apiserver on Linux..."
    cd c:\k
    curl.exe -LO "https://dl.k8s.io/release/v1.30.0/bin/windows/amd64/kubectl.exe"
    .\kubectl.exe --kubeconfig=.\config get node

    Write-Output "All done."
}
catch 
{
    Write-Error $_
}