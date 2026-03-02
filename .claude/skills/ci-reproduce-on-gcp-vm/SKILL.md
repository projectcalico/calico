---
name: ci-reproduce-on-gcp-vm
description: Reproduce CI test failures on a GCP VM matching the CI environment. Use when a CI job fails and the issue cannot be reproduced locally (e.g., kernel-dependent BPF verifier failures, kernel version-specific bugs).
---

## Overview

CI runs Felix tests on GCP VMs using specific Ubuntu image families. The local dev machine may have a different kernel, so some failures only reproduce on the CI kernel. This skill creates a GCP VM matching the CI environment, runs the failing test, and cleans up.

## Prerequisites

- `gcloud` CLI authenticated with access to the `tigera-dev` project
- The calico repo checked out locally with the failing branch

## Step 1: Identify the CI Image Family

Check `felix/.semaphore/fv-prologue` to find the image family for the failing CI job. The mapping is based on `FELIX_TEST_GROUP`:

| Test group pattern | IMAGE_FAMILY | Ubuntu version |
|---|---|---|
| `22.04` | `ubuntu-2204-lts` | 22.04 Jammy |
| `24.04` | `ubuntu-2404-lts-amd64` | 24.04 Noble |
| `25.10` | `ubuntu-2510-amd64` | 25.10 Plucky |

For example, the `bpf-24.04-ipt-with-ut` test group uses `ubuntu-2404-lts-amd64`.

If in doubt, read `felix/.semaphore/fv-prologue` and `.semaphore/vms/vm-bootstrap.sh` for the latest mappings.

## Step 2: Create the VM

```bash
zone=us-central1-a
vm_name=<user>-debug
image_family=ubuntu-2404-lts-amd64  # from Step 1

gcloud config set project tigera-dev
gcloud --quiet compute instances create "${vm_name}" \
  --zone=${zone} \
  --image-family=${image_family} \
  --image-project=ubuntu-os-cloud \
  --machine-type=n4-standard-4 \
  --boot-disk-size=50G \
  --boot-disk-type=hyperdisk-balanced
```

Use `n4-highcpu-4` to match CI more closely (CI uses this for Felix FV).

## Step 3: Wait for SSH and Install Dependencies

The VM bootstrap in CI is done by `.semaphore/vms/vm-bootstrap.sh`. Replicate its key steps:

```bash
ssh_cmd="gcloud --quiet compute ssh --zone=${zone} ubuntu@${vm_name} --"

# Wait for SSH
for i in $(seq 1 10); do
  ${ssh_cmd} echo "SSH ready" && break
  sleep 2
done

# Install prerequisites
${ssh_cmd} "sudo apt-get update -y && sudo apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl software-properties-common"

# Add Docker repo (auto-detect codename)
${ssh_cmd} "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg"
${ssh_cmd} "ubuntu_codename=\$(. /etc/os-release && echo \"\${UBUNTU_CODENAME:-\$VERSION_CODENAME}\") && echo \"deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \$ubuntu_codename stable\" | sudo tee /etc/apt/sources.list.d/docker.list"
${ssh_cmd} "sudo apt-get update -y"

# Install Docker and tools — pin versions to match CI (see .semaphore/vms/vm-bootstrap.sh)
# Noble (24.04): docker-ce=5:27.5.1-1~ubuntu.24.04~noble
# Jammy (22.04): docker-ce=5:20.10.14~3-0~ubuntu-jammy
# If unsure, omit the version pin to get the latest.
${ssh_cmd} "sudo apt-get install -y --no-install-recommends docker-ce docker-ce-cli docker-buildx-plugin containerd.io git make iproute2 wireguard"

# Post-install setup
${ssh_cmd} "sudo usermod -a -G docker ubuntu"
${ssh_cmd} "sudo modprobe ipip"

# Configure Docker with IPv6 (required by many FV tests)
${ssh_cmd} 'echo "{\"ipv6\": true, \"fixed-cidr-v6\": \"2001:db8:1::/64\"}" | sudo tee /etc/docker/daemon.json'
${ssh_cmd} "sudo systemctl restart docker"

# Match CI's sysctl setting (loose reverse path filtering)
${ssh_cmd} "sudo sysctl -w net.ipv4.conf.all.rp_filter=2"
```

## Step 4: Clone Repo and Checkout Branch

```bash
# Get the current branch name
branch=$(git rev-parse --abbrev-ref HEAD)
remote_url=$(git remote get-url origin)

${ssh_cmd} "git clone ${remote_url} calico && cd calico && git checkout ${branch}"
```

If the remote is an SSH URL and the VM doesn't have SSH keys, use the HTTPS URL instead:
```bash
# Convert git@github.com:user/repo.git to https://github.com/user/repo.git
https_url=$(echo "${remote_url}" | sed 's|git@github.com:|https://github.com/|')
${ssh_cmd} "git clone ${https_url} calico && cd calico && git checkout ${branch}"
```

## Step 5: Run the Failing Test

Check the kernel version first to confirm it differs from local:
```bash
${ssh_cmd} "uname -r"
```

Then run the specific test. Common patterns:

```bash
# BPF unit test (e.g., verifier loadability)
${ssh_cmd} "cd calico/felix && make FOCUS=TestPrecompiledBinariesAreLoadable ut-bpf"

# Specific BPF unit test
${ssh_cmd} "cd calico/felix && make FOCUS=TestNATNodePortNoFWD ut-bpf"

# Felix FV test
${ssh_cmd} "cd calico/felix && make fv GINKGO_FOCUS='TestName'"

# BPF FV test
${ssh_cmd} "cd calico/felix && make fv-bpf GINKGO_FOCUS='TestName'"
```

The first run will be slow (pulls Docker build images). Subsequent runs are faster.

## Step 6: Clean Up

Always delete the VM when done:

```bash
gcloud --quiet compute instances delete ${vm_name} --zone=${zone}
```

## Reference: CI Configuration Files

| File | Purpose |
|---|---|
| `felix/.semaphore/fv-prologue` | Maps test groups to image families, sets env vars |
| `.semaphore/vms/vm-bootstrap.sh` | VM startup script (Docker install, sysctl, IPv6) |
| `.semaphore/vms/run-tests-on-vms` | Orchestrates VM creation and test execution |
| `.semaphore/vms/configure-test-vm` | Per-VM configuration after bootstrap |
| `.semaphore/semaphore.yml.d/blocks/20-felix.yml` | Felix CI job definitions and test groups |
