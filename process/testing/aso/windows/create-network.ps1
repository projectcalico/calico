param (
  [parameter(Mandatory = $true)] $Backend
)

#create external network
if (!(Test-Path C:\\k\\helper.psm1))
{
  curl.exe -L https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.psm1 -o C:\\k\\helper.psm1
}
ipmo C:\\k\\helper.psm1

if (!(Test-Path C:\\k\\hns.psm1))
{
  DownloadFile -Url "https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/hns.psm1" -Destination C:\\k\\hns.psm1
  DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -Destination C:\\k\\host-local.exe
}
ipmo C:\\k\\hns.psm1

function Delete-External-Network {
  $network = Get-HNSNetwork | ? name -like External
  Write-Host "Got external network: $network"

  if ($null -ne $network) {
    Write-Host "Removing external network..."
    Remove-HNSNetwork $network
  }
}

function Create-L2Bridge-Network {
  Write-Host "Creating l2bridge network..."
  
  #create external network
  New-HNSNetwork -Type "L2Bridge" -AddressPrefix "10.244.10.0/24" -Gateway "10.244.10.1" -Name "External" -Verbose
  Start-Sleep -s 20s
}

function Create-Overlay-Network {
  Write-Host "Creating overlay network..."

  #Create overlay external network
  New-HNSNetwork -Type "Overlay" -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -SubnetPolicies @(@{Type = "VSID"; VSID = 9999; }) -Verbose
  Start-Sleep -s 20s
}

if ($Backend -eq "l2bridge") {
  Delete-External-Network
  Create-L2Bridge-Network
} elseif ($Backend -eq "overlay") {
  Delete-External-Network
  Create-Overlay-Network
} else {
  Write-Host "Invalid backend. Please specify either 'l2bridge' or 'overlay'."
}