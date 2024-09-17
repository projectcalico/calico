# Replace an existing containerd installation with a specific version of containerd.
# Adapted from https://github.com/kubernetes-sigs/windows-testing/blob/e841a06620a293ab2c286b53f562a97f3397595f/capz/templates/windows-base.yaml#L27-L61

Param(
    [parameter(Mandatory = $false)] $ContainerdVersion="1.7.13"
)

$ErrorActionPreference = 'Stop'
$CONTAINERD_URL="https://github.com/containerd/containerd/releases/download/v${ContainerdVersion}/containerd-${ContainerdVersion}-windows-amd64.tar.gz"
if($CONTAINERD_URL -ne ""){
    # Kubelet service depends on containerd service so make a best effort attempt to stop it
    Stop-Service kubelet -Force -ErrorAction SilentlyContinue
    Stop-Service containerd -Force
    echo "downloading containerd: $CONTAINERD_URL"
    curl.exe --retry 10 --retry-delay 5 -L "$CONTAINERD_URL" --output "c:/k/containerd.tar.gz"
    # Log service state and if any files under containerd director are locked
    Get-Service -Name containerd, kubelet
    $dir = "c:/Program Files/containerd"
    $files = Get-ChildItem $dir -Recurse
    Write-Output "Checking if any files under $dir are locked"
    foreach ($file in $files) {
        $f = $file.FullName
        Write-output "$f"
        $fi = New-Object System.IO.FileInfo $f
        try {
        $fStream = $fi.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            if ($fStream) {
                $fStream.Close()
            }
        } catch {
            Write-Output "Unable to open file: $f"
        }
    }
    Write-Output "Extracting new containerd binaries"
    tar.exe -zxvf c:/k/containerd.tar.gz -C "c:/Program Files/containerd" --strip-components 1

    Write-Output "Starting containerd and kubelet"
    Start-Service containerd
    Start-Service kubelet
    Get-Service -Name containerd, kubelet
}
containerd.exe --version
containerd-shim-runhcs-v1.exe --version
