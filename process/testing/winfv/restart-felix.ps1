# Copy this file to c:\CalicoWindows and run it to restart felix.
# Make sure calico-felix.exe has been copied over to c:\CalicoWindows already.
ipmo "$PSScriptRoot\libs\calico\calico.psm1" -Force

. $PSScriptRoot\config.ps1

$ErrorActionPreference = 'SilentlyContinue'

# Remove CalicoFelix service
Stop-Service CalicoFelix
Remove-FelixService

sleep 5

# you may add code here to copy latest calico-felix.exe

# Remove CalicoFelix logs and flow logs
rm $PSScriptRoot\logs\calico-felix*.log
rm c:\TigeraCalico\flowlogs\*

# Install and start CalicoFelix again
Install-FelixService
Write-Host "Starting CalicoFelix..."
Start-Service CalicoFelix

while ((Get-Service | where Name -Like 'CalicoFelix' | where Status -NE Running) -NE $null) {
    Write-Host "Waiting for the Calico services to be running..."
    Start-Sleep 1
}

Write-Host "Done, the Calico services are running:"
Get-Service | where Name -Like 'CalicoFelix'

sleep 5
