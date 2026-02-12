Param(
  [parameter(Mandatory = $false)] $LinuxPIP="{{.Env.LINUX_PIP}}",
  [parameter(Mandatory = $false)] $KubeVersion="{{.Env.KUBE_VERSION}}",
  [parameter(Mandatory = $false)] $FVType="{{.Env.FV_TYPE}}",
  [parameter(Mandatory = $false)] $WinFvExecutable="win-fv.exe"
)

$Root="c:\\CalicoWindows"

# Set HPC environment variable (ASO provisioner default)
Set-Item -Path env:HPC -Value "true"

# Force powershell to run in 64-bit mode .
if ([Environment]::Is64BitProcess -eq $false) {
    write-warning "This script requires PowerShell 64-bit, relaunching..."
    if (\$myInvocation.Line) {
        &"\$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile \$myInvocation.Line
    }else{
        &"\$env:SystemRoot\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -file "\$(\$myInvocation.InvocationName)" \$args
    }
    exit \$lastexitcode
}

if ($FVType -eq "tigera-felix") {
  # Add config parameters for felix FV.
  $body=@'
# Default settings for EE Felix
$env:FELIX_FLOWLOGSFILEENABLED = "true"
$env:FELIX_FLOWLOGSFILEINCLUDELABELS = "true"
$env:FELIX_FLOWLOGSFILEINCLUDEPOLICIES = "true"
$env:FELIX_FLOWLOGSFILEINCLUDESERVICE = "true"
$env:FELIX_FLOWLOGSENABLENETWORKSETS = "true"
# Extra settings for Felix FV
'@
  Add-Content -Path $Root\config.ps1 -Value $body
}

# Setting up Environment Variable
Set-Item -Path env:KUBECONFIG -Value "C:\\k\\config"
Set-Item -Path env:KUBERNETES_MASTER -Value "https://${LinuxPIP}:6443"
Set-Item -Path env:ETCD_ENDPOINTS -Value "http://${LinuxPIP}:2389"
Set-Item -Path env:BIN -Value "C:\\k"
Set-Item -Path env:PLUGIN -Value "calico"
Set-Item -Path env:CONTAINER_RUNTIME -Value "containerd"
Set-Item -Path env:MAC_PREFIX -Value "0E-2A"
Set-Item -Path env:VSID -Value "4096"
Set-Item -Path env:WINDOWS_OS -Value "Windows2022container"
Set-Item -Path env:REPORT -Value "C:\\k\\report\\report-full.xml"

# create report directory to generate result
if (!(Test-Path c:\k\report))
{
  mkdir -p c:\k\report
}

# executes FV test and generate report in report/result.xml
cd C:\\k
& .\win-fv.exe --ginkgo.focus "Windows" --ginkgo.v > C:\k\report\fv-test.log 2>&1
if ( $LastExitCode -ne 0 ){
  echo $LastExitCode > c:\k\report\error-codes
  if (Test-Path C:\CalicoWindows\logs) {
    cp c:\CalicoWindows\logs\*.log c:\k\report
  }
}

echo "All done" > c:\k\report\done-marker
