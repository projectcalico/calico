Param(
    [parameter(Mandatory = $false)] $LinuxPIP="<your linux pip>",
    [parameter(Mandatory = $false)] $KubeVersion="<your kube version>",
    [parameter(Mandatory = $false)] $OSVersion="<your os version>",
    [parameter(Mandatory = $false)] $ContainerRuntime="<your container runtime>",
    [parameter(Mandatory = $false)] $FVType="<your fv type>",
    [parameter(Mandatory = $false)] $Provisioner="<your fv provisioner>",
    [parameter(Mandatory = $false)] $WinFvExecutable="win-fv.exe"
)

$Root="c:\\CalicoWindows"

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

if ($Provisioner -ne "capz") {
    # Install Calico for Windows
    Invoke-WebRequest https://docs.projectcalico.org/scripts/install-calico-windows.ps1 -OutFile c:\\install-calico-windows.ps1

    c:\\install-calico-windows.ps1 -KubeVersion $KubeVersion

    c:\\CalicoWindows\\kubernetes\\install-kube-services.ps1
    Start-Sleep 10
    Start-Service -Name kubelet
    Start-Service -Name kube-proxy

    # Wait 20 minutes for pod ready
    $Timeout = 1200
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $ip = $null
    while (($timer.Elapsed.TotalSeconds -lt $Timeout) -and ([string]::IsNullOrEmpty($ip))) {
        Start-Sleep -Seconds 20
        $totalSec = $timer.Elapsed.TotalSeconds
        Write-Host "Still waiting for porter pod ready to complete after $totalSec seconds..."
        $ip = c:\k\kubectl.exe --kubeconfig=c:\k\config get pod porter -n demo -o jsonpath='{.status.podIP}'
    }
    $timer.Stop()

    if ([string]::IsNullOrEmpty($ip)) {
        Write-Host "Failed to see porter pod getting ready. exit"
        echo 9 > c:\k\report\error-codes

        cp c:\k\cf-fv-log c:\k\report

        echo y | c:\k\pscp.exe -2 -i c:\k\linux-node.ppk c:\k\report\* ubuntu@${LinuxPIP}:/home/ubuntu/report/
        echo done-marker > c:\k\done-marker
        exit 1
    }
    & c:\k\kubectl.exe --kubeconfig=c:\k\config get pod -n demo -o wide
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

if ($Provisioner -ne "capz") {
    # Use the calico-felix.exe under test. We need to replace the felix service
    # using calico-node.exe.
    cp c:\\k\\calico-felix.exe $Root
    cp c:\\k\\restart-felix.ps1 $Root
    (Get-Content $Root\felix\felix-service.ps1).replace(".\calico-node.exe -felix", ".\calico-felix.exe") | Set-Content $Root\felix\felix-service.ps1 -Force
    & c:\\k\\restart-felix.ps1
}

# Setting up Environment Variable
Set-Item -Path env:KUBECONFIG -Value "C:\\k\\config"
Set-Item -Path env:KUBERNETES_MASTER -Value "https://${LinuxPIP}:6443"
Set-Item -Path env:ETCD_ENDPOINTS -Value "http://${LinuxPIP}:2389"
Set-Item -Path env:BIN -Value "C:\\k"
Set-Item -Path env:PLUGIN -Value "calico"
Set-Item -Path env:MAC_PREFIX -Value "0E-2A"
Set-Item -Path env:VSID -Value "4096"
Set-Item -Path env:WINDOWS_OS -Value "$OSVersion"
Set-Item -Path env:REPORT -Value "C:\\k\\report\\report-full.xml"

# create report directory to generate result
mkdir -p C:\\k\\report
# executes FV test and generate report in report/result.xml
cd C:\\k
& .\win-fv.exe --ginkgo.focus "Windows" --ginkgo.v > C:\k\report\fv-test.log 2>&1
if ( $LastExitCode -ne 0 ){
  echo $LastExitCode > c:\k\report\error-codes
  cp c:\CalicoWindows\logs\*.log c:\k\report
}

if ($Provisioner -ne "capz") {
    cp c:\k\cf-fv-log.txt c:\k\report

    echo y | c:\k\pscp.exe -2 -i c:\k\linux-node.ppk c:\k\report\* ubuntu@${LinuxPIP}:/home/ubuntu/report/
    echo done-marker > done-marker
    echo y | c:\k\pscp.exe -2 -i c:\k\linux-node.ppk done-marker ubuntu@${LinuxPIP}:/home/ubuntu/report/done-marker
}
