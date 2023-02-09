Param(
    [parameter(Mandatory = $false)] $LinuxPIP="<your linux pip>",
    [parameter(Mandatory = $false)] $KubeVersion="<your kube version>",
    [parameter(Mandatory = $false)] $OSVersion="<your os version>",
    [parameter(Mandatory = $false)] $ContainerRuntime="<your container runtime>",
    [parameter(Mandatory = $false)] $ContainerdVersion="<your containerd version>"
)

# Force powershell to run in 64-bit mode .
if (\$env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    write-warning "This script requires PowerShell 64-bit, relaunching..."
    if (\$myInvocation.Line) {
        &"\$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile \$myInvocation.Line
    }else{
        &"\$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -file "\$(\$myInvocation.InvocationName)" \$args
    }
    exit \$lastexitcode
}

#Setting up Environment Variable
Set-Item -Path env:KUBECONFIG -Value "C:\\k\\config"
Set-Item -Path env:KUBERNETES_MASTER -Value "https://${LinuxPIP}:6443"
Set-Item -Path env:ETCD_ENDPOINTS -Value "http://${LinuxPIP}:2389"
Set-Item -Path env:BIN -Value "C:\\k"
Set-Item -Path env:PLUGIN -Value "calico"
Set-Item -Path env:DATASTORE_TYPE -Value "etcdv3"
Set-Item -Path env:CONTAINER_RUNTIME -Value "$ContainerRuntime"
Set-Item -Path env:CNI_VERSION -Value "0.3.0"
Set-Item -Path env:MAC_PREFIX -Value "0E-2A"
Set-Item -Path env:VSID -Value "4096"
Set-Item -Path env:WINDOWS_OS -Value "$OSVersion"
Set-Item -Path env:REPORT -Value "C:\\k\\report\\report-l2bridge.xml"

# Install containerd if not present
if (!(Test-Path "$Env:ProgramFiles\containerd"))
{
  curl.exe -L https://github.com/containerd/containerd/releases/download/v$ContainerdVersion/containerd-$ContainerdVersion-windows-amd64.tar.gz -o c:\containerd-windows-amd64.tar.gz
  cd c:\
  tar.exe xvf c:\containerd-windows-amd64.tar.gz | Out-Null

  # containerd tarball contains a bin folder containing the exe files.
  # containerd expects to be in c:\Program Files
  Copy-Item -Path "c:\bin" -Destination "$Env:ProgramFiles\containerd" -Recurse -Force
  cd $Env:ProgramFiles\containerd\

  # Generate and save the config file.
  .\containerd.exe config default | Out-File config.toml -Encoding ascii

  # Register but do not start the service.
  .\containerd.exe --register-service

  # Exclude containerd from Windows Defender Scans
  Add-MpPreference -ExclusionProcess "$Env:ProgramFiles\containerd\containerd.exe"

  # Go back to script root
  cd $PSScriptRoot
}

if ($ContainerRuntime -EQ "containerd")
{
  if ((Get-Service | where Name -EQ 'containerd' | where Status -EQ Running) -EQ $null)
  {
    Start-Service -Name containerd
  }
  if ((Get-Service | where Name -EQ 'docker' | where Status -EQ Running) -NE $null)
  {
    Stop-Service -Name docker
  }

  if ( "$OSVersion" -eq "Windows1809container" ) {
     C:\bin\ctr.exe -n k8s.io images pull mcr.microsoft.com/windows/servercore:1809 | Out-Null
  } elseif ( "$OSVersion" -eq "Windows1903container" ) {
     C:\bin\ctr.exe -n k8s.io images pull mcr.microsoft.com/windows/servercore/insider:10.0.18317.1000 | Out-Null
  }
}
else
{
  if ( "$OSVersion" -eq "Windows1809container" ) {
     docker pull mcr.microsoft.com/windows/servercore:1809
  } elseif ( "$OSVersion" -eq "Windows1903container" ) {
     docker pull mcr.microsoft.com/windows/servercore/insider:10.0.18317.1000
  }
}

#create external network
if (!(Test-Path C:\\k\\helper.psm1))
{
  Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.psm1 -OutFile C:\\k\\helper.psm1
}
ipmo C:\\k\\helper.psm1
DownloadFile -Url "https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/hns.psm1" -Destination C:\\k\\hns.psm1
ipmo C:\\k\\hns.psm1
DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -Destination C:\\k\\host-local.exe
#create external network
New-HNSNetwork -Type "L2Bridge" -AddressPrefix "10.244.10.0/24" -Gateway "10.244.10.1" -Name "External" -Verbose
#sleep
Start-Sleep -s 15

#create report directory to generate result
mkdir -p C:\\k\\report
#executes FV test and generate report in report/result.xml
cd C:\\k
& .\win-fv.exe --ginkgo.focus "l2bridge network" > C:\k\report\fv-test-l2bridge.log 2>&1
if ( $LastExitCode -ne 0 ){
  echo $LastExitCode > c:\k\report\error-codes
}

#Delete l2bridge external network
Get-HNSNetwork | ? name -like External | Remove-HNSNetwork
Start-Sleep -s 20
#Create overlay external network
New-HNSNetwork -Type "Overlay" -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -SubnetPolicies @(@{Type = "VSID"; VSID = 9999; }) -Verbose
Start-Sleep -s 20

Set-Item -Path env:REPORT -Value "C:\\k\\report\\report-overlay.xml"
& .\win-fv.exe --ginkgo.focus "overlay network" > C:\k\report\fv-test-overlay.log 2>&1
if ( $LastExitCode -ne 0 ){
  echo $LastExitCode >> c:\k\report\error-codes
}

cp .\cf-fv-log c:\k\report

cat C:\\k\\report\\report-l2bridge.xml C:\\k\\report\\report-overlay.xml | sc C:\\k\\report\\report.xml
echo y | c:\k\pscp.exe -2 -i c:\k\linux-node.ppk c:\k\report\* ubuntu@${LinuxPIP}:/home/ubuntu/report/
echo done-marker > done-marker
echo y | c:\k\pscp.exe -2 -i c:\k\linux-node.ppk done-marker ubuntu@${LinuxPIP}:/home/ubuntu/report/done-marker


