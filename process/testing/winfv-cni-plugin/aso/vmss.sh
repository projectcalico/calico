#!/bin/bash
# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Azure Service Operator v2 VirtualMachine Management Script
# 
# This script manages Azure VirtualMachine resources using Azure Service Operator v2.
# It has been enhanced with ASO v2 best practices including:
#
# Usage:
#   ./vmss.sh create      - Create VirtualMachine resources with ASO v2
#   ./vmss.sh info        - Show VM connection information  
#   ./vmss.sh confirm-ssh - Verify SSH connectivity
#   ./vmss.sh diagnose    - Diagnose ASO v2 resource status
#   ./vmss.sh delete      - Delete ASO v2 resources and cleanup namespace
#
# Requirements:
# - kubectl configured with cluster access  
# - gomplate for template processing
# - Azure credentials (AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
#

. ./export-env.sh

. ../../util/utils.sh

: ${KUBECTL:=./bin/kubectl}
: ${GOMPLATE:=./bin/gomplate}

# Trap function to run diagnostics on non-zero exit
function exit_handler() {
  local exit_code=$?
  
  # Only run diagnostics if:
  # 1. Exit code is non-zero (failure)  
  # 2. We're not already in the diagnose command (avoid recursion)
  if [[ $exit_code -ne 0 && "$1" != "diagnose" ]]; then
    log_warning "Script failed with exit code $exit_code, running diagnostics..."
    echo "=================================="
    echo "AUTOMATIC DIAGNOSTICS ON FAILURE:"
    echo "=================================="
    diagnose_aso_resources
    pause-for-debug
  fi
}

# Set up the trap to run on script exit
trap exit_handler EXIT


function ensure_aso_credentials() {
  # Configure namespaced ASO credentials only
  log_info "Configuring namespaced ASO v2 credentials..."
  
  # Verify required environment variables
  : "${AZURE_SUBSCRIPTION_ID:?Environment variable empty or not defined.}"
  : "${AZURE_TENANT_ID:?Environment variable empty or not defined.}"
  : "${AZURE_CLIENT_ID:?Environment variable empty or not defined.}"
  : "${AZURE_CLIENT_SECRET:?Environment variable empty or not defined.}"
  
  # Create namespace for our resources
  ${KUBECTL} create namespace winfv --dry-run=client -o yaml | ${KUBECTL} apply -f -
  
  log_info "Creating namespaced ASO credentials in winfv namespace..."
  
  # Create the namespaced credential secret
  cat <<EOF | ${KUBECTL} apply -f -
apiVersion: v1
kind: Secret
metadata:
   name: aso-credential
   namespace: winfv
stringData:
  AZURE_SUBSCRIPTION_ID: "$AZURE_SUBSCRIPTION_ID"
  AZURE_TENANT_ID: "$AZURE_TENANT_ID"
  AZURE_CLIENT_ID: "$AZURE_CLIENT_ID"
  AZURE_CLIENT_SECRET: "$AZURE_CLIENT_SECRET"
EOF
  
  if [[ $? -eq 0 ]]; then
    log_info "Namespaced ASO credentials created successfully"
  else
    log_error "Failed to create namespaced ASO credentials"
    return 1
  fi
}

function apply_azure_crds() {
  log_info "Starting ASO v2 resource deployment"
  
  # Ensure ASO credentials are available
  ensure_aso_credentials
  
  # Generate and export a secure password for Windows RDP.
  export PASSWORD=$(openssl rand -base64 16)
  export PASSWORD_BASE64=$(echo -n "$PASSWORD" | base64)
  cat << EOF > password.txt
-------------Connect to Windows Instances-------------
username: winfv 
password: $PASSWORD
password-base64: $PASSWORD_BASE64
EOF
  log_info "Generated Windows credentials: username=winfv, password saved to password.txt"

  rm ${SSH_KEY_FILE} || true
  ssh-keygen -m PEM -t rsa -b 2048 -f "${SSH_KEY_FILE}" -N '' -C "" 1>/dev/null
  log_info "Machine SSH key generated in ${SSH_KEY_FILE}"
  export PUBLIC_KEY=$(cat ${SSH_KEY_FILE}.pub)

  rm -rf infra/manifests || true
  ${GOMPLATE} --input-dir infra/templates --output-dir infra/manifests
  log_info "Generated manifests with gomplate"

  # Apply resources in dependency order with ASO v2 patterns
  log_info "Applying Azure resources with ASO v2..."
  
  # Step 1: Resource Group (foundational)  
  log_info "Creating Resource Group..."
  ${KUBECTL} apply -f infra/manifests/resource-group.yaml

  if ! wait_for_aso_resource "resourcegroup" "$AZURE_RESOURCE_GROUP" "winfv" "300s"; then
    log_error "Failed to create Resource Group"
    return 1
  fi
  
  # Step 2: Networking components
  log_info "Creating networking components..."
  ${KUBECTL} apply -f infra/manifests/vnet.yaml
  ${KUBECTL} apply -f infra/manifests/security-group.yaml
  
  # Wait for VNet to be ready before proceeding
  if ! wait_for_aso_resource "virtualnetwork" "vnet-winfv" "winfv" "300s"; then
    log_error "Failed to create Virtual Network"
    return 1
  fi
  
  # Step 3: Secrets
  log_info "Creating secrets..."
  ${KUBECTL} apply -f infra/manifests/password.yaml
  
  # Step 4: Virtual Machines (dependent on network resources)
  log_info "Creating Virtual Machines..."
  ${KUBECTL} apply -f infra/manifests/vmss-linux.yaml
  ${KUBECTL} apply -f infra/manifests/vmss-windows.yaml
  
  # Wait for VMs with extended timeout
  local vm_resources=("vm-linux" "vm-windows")
  local failed_vms=()
  
  for vm in "${vm_resources[@]}"; do
    log_info "Waiting for VirtualMachine: $vm"
    if ! wait_for_aso_resource "virtualmachine" "$vm" "winfv" "$ASO_TIMEOUT_DEFAULT"; then
      log_error "VirtualMachine $vm failed to become ready"
      failed_vms+=("$vm")
      
      # Provide diagnostic information
      log_info "Diagnostic information for $vm:"
      ${KUBECTL} describe virtualmachine "$vm" -n winfv | tail -20
    else
      log_info "VirtualMachine $vm is ready"
    fi
  done
  
  if [[ ${#failed_vms[@]} -gt 0 ]]; then
    log_error "Failed VirtualMachine resources: ${failed_vms[*]}"
    log_info "Use '${KUBECTL} describe virtualmachine <name> -n winfv' for more details"
    return 1
  fi
  
  log_info "All ASO v2 resources applied and reconciled successfully"
}

# Default timeout for ASO operations (15 minutes for VMs)
: ${ASO_TIMEOUT_DEFAULT:=900s}

# Wait for ASO v2 resources to become ready using condition-based checking
function wait_for_aso_resource() {
  local resource_type="$1"
  local resource_name="$2"
  local namespace="$3"
  local timeout="${4:-$ASO_TIMEOUT_DEFAULT}"
  
  log_info "Waiting for $resource_type/$resource_name in namespace $namespace (timeout: $timeout)..."
  
  # First, wait for the resource to exist (up to 30 seconds)
  local wait_count=0
  while ! ${KUBECTL} get "$resource_type/$resource_name" -n "$namespace" >/dev/null 2>&1; do
    if [[ $wait_count -ge 30 ]]; then
      log_fail "$resource_type/$resource_name does not exist after 30 seconds"
      return 1
    fi
    log_info "Waiting for $resource_type/$resource_name to be created... (${wait_count}s)"
    sleep 1
    ((wait_count++))
  done
  
  # Now wait for the Ready condition
  if ${KUBECTL} wait --for=condition=Ready "$resource_type/$resource_name" -n "$namespace" --timeout="$timeout"; then
    log_info "$resource_type/$resource_name is ready"
    return 0
  else
    log_fail "$resource_type/$resource_name failed to become ready within $timeout"
    
    # Show diagnostic information
    log_info "Resource status for debugging:"
    ${KUBECTL} describe "$resource_type" "$resource_name" -n "$namespace" | tail -10
    return 1
  fi
}

function delete_azure_crds() {
  log_info "Starting ASO v2 resource cleanup"
  
  # Check if namespace exists before attempting deletion
  if ! ${KUBECTL} get namespace winfv &>/dev/null; then
    log_info "Namespace winfv does not exist, nothing to clean up"
    return 0
  fi
  
  log_info "Deleting ASO resources in reverse dependency order..."
  
  # Step 1: Delete VirtualMachines first (highest level resources)
  log_info "Deleting VirtualMachines..."
  if ${KUBECTL} get virtualmachines -n winfv &>/dev/null; then
    ${KUBECTL} delete virtualmachines --all -n winfv --timeout=300s
    
    # Wait for VirtualMachines to be completely gone
    log_info "Waiting for VirtualMachines to be deleted..."
    local timeout=500
    local count=0
    while ${KUBECTL} get virtualmachines -n winfv &>/dev/null && [[ $count -lt $timeout ]]; do
      sleep 5
      count=$((count + 5))
      if (( count % 30 == 0 )); then
        log_info "Still waiting for VirtualMachines to be deleted... (${count}s elapsed)"
      fi
    done
    
    if ${KUBECTL} get virtualmachines -n winfv &>/dev/null; then
      log_warn "VirtualMachines still exist after timeout, but continuing..."
    else
      log_info "VirtualMachines deleted successfully"
    fi
  fi
  
  # Step 2: Delete NetworkInterfaces and PublicIPAddresses  
  log_info "Deleting NetworkInterfaces and PublicIPAddresses..."
  if ${KUBECTL} get networkinterfaces -n winfv &>/dev/null; then
    ${KUBECTL} delete networkinterfaces --all -n winfv --timeout=180s
  fi
  if ${KUBECTL} get publicipaddresses -n winfv &>/dev/null; then
    ${KUBECTL} delete publicipaddresses --all -n winfv --timeout=180s
  fi
  
  # Step 3: Delete NetworkSecurityGroups
  log_info "Deleting NetworkSecurityGroups..."
  if ${KUBECTL} get networksecuritygroups -n winfv &>/dev/null; then
    ${KUBECTL} delete networksecuritygroups --all -n winfv --timeout=180s
  fi
  
  # Step 4: Delete VirtualNetworks
  log_info "Deleting VirtualNetworks..."
  if ${KUBECTL} get virtualnetworks -n winfv &>/dev/null; then
    ${KUBECTL} delete virtualnetworks --all -n winfv --timeout=180s
  fi
  
  # Step 5: Delete ResourceGroup (foundational resource, last)
  log_info "Deleting ResourceGroup..."
  if ${KUBECTL} get resourcegroups -n winfv &>/dev/null; then
    ${KUBECTL} delete resourcegroups --all -n winfv --timeout=300s
  fi
  
  # Step 6: Wait for all ASO resources to be completely gone
  log_info "Waiting for all ASO resources to be cleaned up..."
  local timeout=600  # 10 minutes total timeout
  local count=0
  local check_interval=10
  
  while [[ $count -lt $timeout ]]; do
    local remaining_resources=$(${KUBECTL} get virtualmachines,publicipaddresses,networkinterfaces,networksecuritygroups,virtualnetworks,resourcegroups -n winfv --no-headers 2>/dev/null | wc -l)
    
    if [[ $remaining_resources -eq 0 ]]; then
      log_info "All ASO resources have been cleaned up successfully"
      break
    fi
    
    sleep $check_interval
    count=$((count + check_interval))
    
    if (( count % 60 == 0 )); then
      log_info "Still waiting for ASO cleanup... (${count}s elapsed, $remaining_resources resources remaining)"
      ${KUBECTL} get virtualmachines,publicipaddresses,networkinterfaces,networksecuritygroups,virtualnetworks,resourcegroups -n winfv --no-headers 2>/dev/null || true
    fi
  done
  
  # Step 7: Check if any resources are still stuck
  local final_resources=$(${KUBECTL} get virtualmachines,publicipaddresses,networkinterfaces,networksecuritygroups,virtualnetworks,resourcegroups -n winfv --no-headers 2>/dev/null | wc -l)
  
  if [[ $final_resources -gt 0 ]]; then
    log_warn "Some ASO resources are still present after cleanup timeout:"
    ${KUBECTL} get virtualmachines,publicipaddresses,networkinterfaces,networksecuritygroups,virtualnetworks,resourcegroups -n winfv 2>/dev/null || true
    log_warn "You may need to manually delete stuck resources or check Azure portal for remaining resources"
    return 1
  fi
  
  # Step 8: Now safe to delete the namespace
  log_info "All ASO resources cleaned up, deleting namespace..."
  ${KUBECTL} delete namespace winfv --timeout=60s
  
  if [[ $? -eq 0 ]]; then
    log_info "ASO v2 resource cleanup completed successfully"
  else
    log_error "Failed to delete namespace winfv"
    return 1
  fi
}

function show_connections() {
  # Wait for vm deployments with ASO v2 patterns
  log_info "show_connections started..."
  
  log_info "Ensuring vm-linux is ready with ASO v2 status check..."
  if ! wait_for_aso_resource "virtualmachine" "vm-linux" "winfv" "480s"; then
    log_error "vm-linux did not become ready in time"
    return 1
  fi
  
  # Get IP addresses from ASO CRDs
  log_info "Getting Linux VM IP addresses from ASO resources..."
  LINUX_PIP=$(${KUBECTL} get networkinterface nic-linux -n winfv -o jsonpath='{.status.ipConfigurations[0].privateIPAddress}' 2>/dev/null || echo "")
  LINUX_EIP=$(${KUBECTL} get publicipaddress pip-linux -n winfv -o jsonpath='{.status.ipAddress}' 2>/dev/null || echo "")
  
  if [[ -z "$LINUX_EIP" || -z "$LINUX_PIP" ]]; then
    log_error "Failed to retrieve IP addresses for vm-linux from ASO resources"
    log_info "Checking ASO resource status for debugging..."
    ${KUBECTL} get networkinterface nic-linux -n winfv -o yaml | grep -A 10 "status:" || true
    ${KUBECTL} get publicipaddress pip-linux -n winfv -o yaml | grep -A 10 "status:" || true
    return 1
  fi
  
  log_info "vm-linux is ready. PIP:$LINUX_PIP, EIP:$LINUX_EIP"

  log_info "Ensuring vm-windows is ready with ASO v2 status check..."
  if ! wait_for_aso_resource "virtualmachine" "vm-windows" "winfv" "480s"; then
    log_error "vm-windows did not become ready in time"
    return 1
  fi
  
  # Get IP addresses from ASO CRDs for Windows VM
  log_info "Getting Windows VM IP addresses from ASO resources..."
  WINDOWS_PIP=$(${KUBECTL} get networkinterface nic-windows -n winfv -o jsonpath='{.status.ipConfigurations[0].privateIPAddress}' 2>/dev/null || echo "")
  WINDOWS_EIP=$(${KUBECTL} get publicipaddress pip-windows -n winfv -o jsonpath='{.status.ipAddress}' 2>/dev/null || echo "")
  
  if [[ -z "$WINDOWS_EIP" || -z "$WINDOWS_PIP" ]]; then
    log_error "Failed to retrieve IP addresses for vm-windows from ASO resources"
    log_info "Checking ASO resource status for debugging..."
    ${KUBECTL} get networkinterface nic-windows -n winfv -o yaml | grep -A 10 "status:" || true
    ${KUBECTL} get publicipaddress pip-windows -n winfv -o yaml | grep -A 10 "status:" || true
    return 1
  fi
  
  log_info "vm-windows is ready. PIP:$WINDOWS_PIP, EIP:$WINDOWS_EIP"

  # Setup connection info
  MASTER_CONNECT_COMMAND="ssh -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 winfv@${LINUX_EIP}"
  WINDOWS_CONNECT_COMMAND="ssh -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 winfv@${WINDOWS_EIP} powershell"

  WIN_PASSWORD=$(grep "password:" ./password.txt | awk -F':' '{print $2}')

  cat << EOF > connect.txt
-------------Connect to Linux Master Instances--------
${MASTER_CONNECT_COMMAND}

-------------Connect to Windows Instances-------------
RDP://${WINDOWS_EIP} user: winfv password:$WIN_PASSWORD
${WINDOWS_CONNECT_COMMAND}
EOF
  echo
  cat connect.txt

  export LINUX_EIP LINUX_PIP WINDOWS_EIP WINDOWS_PIP MASTER_CONNECT_COMMAND WINDOWS_CONNECT_COMMAND CONTAINERD_VERSION

  echo
  echo "Generating helper files"
  echo '${MASTER_CONNECT_COMMAND} "$@"' > ./ssh-node-linux.sh
  chmod +x ./ssh-node-linux.sh

  cat << EOF > ssh-node-windows.sh
#usage: ./ssh-node-windows.sh "Restart-Computer -force"
${WINDOWS_CONNECT_COMMAND} \$1
EOF
  chmod +x ./ssh-node-windows.sh

  cat << EOF > scp-to-windows.sh
#---------Copy files to windows--------
#usage: ./scp-to-windows.sh kubeconfig c:\\\\k\\\\kubeconfig
#usage: ./scp-to-windows.sh images/ebpf-for-windows-c-temp.zip 'c:\\'
scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10 \$1 winfv@${WINDOWS_EIP}:\$2
EOF
  chmod +x ./scp-to-windows.sh


  cat << EOF > scp-from-windows.sh
#---------Copy files from windows--------
#usage: ./scp-from-windows.sh c:\\k\\calico.log ./calico.log
scp -i ${SSH_KEY_FILE} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=10 winfv@${WINDOWS_EIP}:\$1 \$2
EOF
  chmod +x ./scp-from-windows.sh

  echo "show_connections done."; echo
}

# With static IP allocation, VMs should have stable IP addresses once ready.
# This function attempts to SSH into the VM.
function confirm-nodes-ssh() {
  log_info "Starting SSH connectivity confirmation for VMs..."
  show_connections
  
  log_info "Testing SSH connectivity with retry logic..."
  
  # Helper function to test SSH connectivity with retries
  test_ssh_connectivity() {
    local vm_name="$1"
    local ssh_command="$2"
    local timeout=900  # 15 minutes (increased from 5 minutes for Windows VM boot time)
    local retry_delay=30  # Increased from 15 seconds for less noise
    local start_time=$(date +%s)
    
    log_info "Testing $vm_name SSH connectivity..."
    
    while true; do
      # Use timeout to prevent SSH from hanging indefinitely
      if timeout 30 $ssh_command "echo 'SSH test successful'" >/dev/null 2>&1; then
        log_info "$vm_name SSH connectivity test passed"
        return 0
      fi
      
      local current_time=$(date +%s)
      local elapsed=$((current_time - start_time))
      
      if [[ $elapsed -ge $timeout ]]; then
        log_fail "SSH connectivity test to $vm_name failed after 15 minutes of retries"
        return 1
      fi
      
      log_info "$vm_name SSH test failed, retrying in ${retry_delay} seconds... (elapsed: ${elapsed}s)"
      
      # Show VM status every 2 minutes to help with debugging
      if [[ $((elapsed % 120)) -eq 0 ]] && [[ $elapsed -gt 0 ]]; then
        log_info "Checking $vm_name status after ${elapsed}s..."
        if [[ "$vm_name" == "Windows VM" ]]; then
          ${KUBECTL} get vm vm-windows -n winfv -o jsonpath='{.status.conditions[*].type}:{.status.conditions[*].status} ' 2>/dev/null || true
          echo ""
          ${KUBECTL} get virtualmachinesextension vm-windows-openssh -n winfv -o jsonpath='{.status.provisioningState}' 2>/dev/null && echo " (OpenSSH extension)" || true
        else
          ${KUBECTL} get vm vm-linux -n winfv -o jsonpath='{.status.conditions[*].type}:{.status.conditions[*].status} ' 2>/dev/null || true
          echo ""
        fi
      fi
      
      sleep $retry_delay
    done
  }
  
  # Test both VMs
  if ! test_ssh_connectivity "Linux VM" "./ssh-node-linux.sh"; then
    exit 1
  fi
  
  if ! test_ssh_connectivity "Windows VM" "./ssh-node-windows.sh"; then
    exit 1
  fi
  
  log_info "All SSH connectivity tests completed successfully"
}

function diagnose_aso_resources() {
  log_info "Diagnosing ASO v2 resources..."
  
  # Check if ASO is running
  log_info "Checking ASO v2 controller status..."
  if ${KUBECTL} get deployment azureserviceoperator-controller-manager -n azureserviceoperator-system &>/dev/null; then
    ${KUBECTL} get pods -n azureserviceoperator-system
  else
    log_warn "ASO v2 controller not found"
  fi
  
  # Check namespace and resources
  if ${KUBECTL} get namespace winfv &>/dev/null; then
    log_info "ASO resources in winfv namespace:"
    ${KUBECTL} get virtualmachines,publicipaddresses,networkinterfaces,networksecuritygroups,virtualnetworks,resourcegroups -n winfv -o wide 2>/dev/null || log_warn "No ASO resources found"
    
    # Check for stuck finalizers
    log_info "Checking resources with finalizers:"
    echo "=== Main ASO Resources ==="
    ${KUBECTL} get virtualmachines,publicipaddresses,networkinterfaces,networksecuritygroups,virtualnetworks,resourcegroups -n winfv -o jsonpath='{range .items[*]}{.kind}/{.metadata.name}: {.metadata.finalizers}{"\n"}{end}' 2>/dev/null || true
    
    echo "=== VM Extensions ==="
    ${KUBECTL} get virtualmachinesextensions -n winfv -o jsonpath='{range .items[*]}{.kind}/{.metadata.name}: {.metadata.finalizers}{"\n"}{end}' 2>/dev/null || true
    
    echo "=== Security Rules and Subnets ==="
    ${KUBECTL} get networksecuritygroupssecurityrules,virtualnetworkssubnets -n winfv -o jsonpath='{range .items[*]}{.kind}/{.metadata.name}: {.metadata.finalizers}{"\n"}{end}' 2>/dev/null || true
    
    # Check credential status
    log_info "Checking ASO credentials:"
    if ${KUBECTL} get secret aso-credential -n winfv &>/dev/null; then
      echo "✓ aso-credential secret exists in winfv namespace"
    else
      echo "✗ aso-credential secret NOT found in winfv namespace - this explains the credential errors!"
      echo "  Re-run './vmss.sh create' to recreate the required credentials"
    fi
    
    # Show detailed status for VMs
    log_info "Detailed VirtualMachine status:"
    for vm in vm-linux vm-windows; do
      if ${KUBECTL} get virtualmachine $vm -n winfv &>/dev/null; then
        echo "--- VirtualMachine: $vm ---"
        ${KUBECTL} get virtualmachine $vm -n winfv -o yaml | grep -A 20 "status:" | grep -E "(conditions|ready|message|reason)"
      fi
    done
  else
    log_info "Namespace winfv does not exist"
  fi
}

case $1 in
  create)
    apply_azure_crds
    ;;
  info)
    show_connections
    ;;
  confirm-ssh)
    confirm-nodes-ssh
    ;;
  diagnose)
    diagnose_aso_resources
    ;;
  delete)
    delete_azure_crds
    ;;
  *)
    echo "vmss.sh [create|info|confirm-ssh|diagnose|delete] - manages VirtualMachine resources with ASO v2"
    echo ""
    echo "Commands:"
    echo "  create       - Create Azure VirtualMachine resources using ASO v2"
    echo "  info         - Show VM connection information"
    echo "  confirm-ssh  - Verify SSH connectivity to VMs"
    echo "  diagnose     - Diagnose ASO v2 resource status and finalizers"
    echo "  delete       - Delete ASO v2 resources and cleanup namespace"
    echo ""
    ;;
esac

