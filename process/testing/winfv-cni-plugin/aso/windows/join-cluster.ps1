# Join Windows node to Kubernetes cluster
param(
    [Parameter(Mandatory=$true)]
    [string]$ApiServerAddress,
    
    [Parameter(Mandatory=$true)]
    [string]$JoinArgs,
    
    [string]$WindowsEip = ""
)

$KUBE_BIN_DIR = "C:\k"

# Ensure PATH includes C:\k
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine")

Write-Host "Joining cluster at ${ApiServerAddress}..."
Write-Host "Using kubeadm at: $KUBE_BIN_DIR\kubeadm.exe"
Write-Host "Kubelet location: $KUBE_BIN_DIR\kubelet.exe"

# Verify kubelet exists
if (!(Test-Path "$KUBE_BIN_DIR\kubelet.exe")) {
    Write-Error "kubelet.exe not found at $KUBE_BIN_DIR\kubelet.exe"
    Start-Sleep -Seconds 600
    exit 1
}

# Print the actual join command
Write-Host ""
Write-Host "=========================================="
Write-Host "Executing kubeadm join command:"
Write-Host "$KUBE_BIN_DIR\kubeadm.exe join $JoinArgs --cri-socket npipe:////./pipe/containerd-containerd"
Write-Host "=========================================="
Write-Host ""

# Run kubeadm join with full path
$joinResult = & $KUBE_BIN_DIR\kubeadm.exe join $JoinArgs --cri-socket npipe:////./pipe/containerd-containerd

# Check if join failed
if ($LASTEXITCODE -ne 0) {
    Write-Error "Kubeadm join failed with exit code $LASTEXITCODE"
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "Join failed! Sleeping for 10 minutes for debugging..."
    if ($WindowsEip) {
        Write-Host "You can SSH to this node at: $WindowsEip"
    }
    Write-Host "=========================================="
    Start-Sleep -Seconds 600
    exit $LASTEXITCODE
}

Write-Host "Successfully joined the cluster!"

