# This script is adapated from https://raw.githubusercontent.com/microsoft/Windows-Containers/Main/helpful_tools/Install-ContainerdRuntime/install-containerd-runtime.ps1
# Reference: https://learn.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment?tabs=containerd

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

# Don't show progress bar. 
# Without this setting, Windows will hit error: Win32 internal error "Access is denied" 0x5 occurred while reading the console output buffer.
$ProgressPreference = "SilentlyContinue"

$Force = $true

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

    Write-Output "Restart computer ..."

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

}
