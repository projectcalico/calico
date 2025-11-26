# Use PrepareNode.ps1 from sig-windows-tools to set up Kubernetes binaries
param(
    [string]$K8sVersion = "v1.33.0"
)

$KUBE_BIN_DIR = "C:\k"

# Ensure C:\k directory exists
if (!(Test-Path $KUBE_BIN_DIR)) {
    New-Item -ItemType Directory -Path $KUBE_BIN_DIR -Force
}

Write-Host "Downloading PrepareNode.ps1 from sig-windows-tools..."
curl.exe -L -o PrepareNode.ps1 https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/hostprocess/PrepareNode.ps1

if (!(Test-Path ".\PrepareNode.ps1")) {
    Write-Error "Failed to download PrepareNode.ps1"
    exit 1
}

Write-Host "Running PrepareNode.ps1 to install Kubernetes binaries (version: $K8sVersion)..."
.\PrepareNode.ps1 -KubernetesVersion $K8sVersion

if ($LASTEXITCODE -ne 0) {
    Write-Error "PrepareNode.ps1 failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Kubernetes binaries installed successfully"
Write-Host "Verifying installations..."
if (Test-Path "$KUBE_BIN_DIR\kubeadm.exe") {
    Write-Host "Kubeadm version: $(& $KUBE_BIN_DIR\kubeadm.exe version)"
} else {
    Write-Error "kubeadm.exe not found at $KUBE_BIN_DIR\kubeadm.exe"
    exit 1
}

if (Test-Path "$KUBE_BIN_DIR\kubelet.exe") {
    Write-Host "Kubelet version: $(& $KUBE_BIN_DIR\kubelet.exe --version)"
} else {
    Write-Error "kubelet.exe not found at $KUBE_BIN_DIR\kubelet.exe"
    exit 1
}


