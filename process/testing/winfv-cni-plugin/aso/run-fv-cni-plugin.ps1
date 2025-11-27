Param(
  [parameter(Mandatory = $true)] $Backend,
  [parameter(Mandatory = $false)] $LinuxPIP="{{.Env.LINUX_PIP}}",
  [parameter(Mandatory = $false)] $LinuxAPIServerPort="{{.Env.APISERVER_PORT}}"
)

#Setting up Environment Variable
Set-Item -Path env:KUBECONFIG -Value "C:\\k\\config"
Set-Item -Path env:KUBERNETES_MASTER -Value "https://${LinuxPIP}:${LinuxAPIServerPort}"
Set-Item -Path env:ETCD_ENDPOINTS -Value "http://${LinuxPIP}:2389"
Set-Item -Path env:BIN -Value "C:\\k"
Set-Item -Path env:PLUGIN -Value "calico"
Set-Item -Path env:DATASTORE_TYPE -Value "etcdv3"
Set-Item -Path env:CONTAINER_RUNTIME -Value "containerd"
Set-Item -Path env:CNI_VERSION -Value "0.3.0"
Set-Item -Path env:MAC_PREFIX -Value "0E-2A"
Set-Item -Path env:VSID -Value "4096"
Set-Item -Path env:WINDOWS_OS -Value "Windows1809container"

if (!(Test-Path C:\\k\\helper.psm1))
{
  curl.exe -L https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/helper.psm1 -o C:\\k\\helper.psm1
}
ipmo C:\\k\\helper.psm1
DownloadFile -Url "https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/hns.psm1" -Destination C:\\k\\hns.psm1
ipmo C:\\k\\hns.psm1
DownloadFile -Url  "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/l2bridge/cni/host-local.exe" -Destination C:\\k\\host-local.exe

#create report directory to generate result
if (!(Test-Path C:\\k\\report))
{
  mkdir -p C:\\k\\report
}

#executes FV test and generate report in report/result.xml
cd C:\\k

if ($Backend -eq "l2bridge") {
  Set-Item -Path env:REPORT -Value "C:\\k\\report\\report-l2bridge.xml"
  .\win-fv.exe --ginkgo.focus "l2bridge network" | Tee-Object -FilePath C:\k\report\fv-test-l2bridge.log 2>&1
  if ( $LastExitCode -ne 0 ){
    echo $LastExitCode > c:\k\report\error-codes
  }
} elseif ($Backend -eq "overlay") {
  Set-Item -Path env:REPORT -Value "C:\\k\\report\\report-overlay.xml"
  .\win-fv.exe --ginkgo.focus "overlay network" | Tee-Object -FilePath C:\k\report\fv-test-overlay.log 2>&1
  if ( $LastExitCode -ne 0 ){
    echo $LastExitCode >> c:\k\report\error-codes
  }
} else {
  Write-Host "Invalid backend. Please specify either 'l2bridge' or 'overlay'."
}

echo "All done" > c:\k\report\done-marker