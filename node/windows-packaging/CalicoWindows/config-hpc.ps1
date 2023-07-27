# Copyright (c) 2023 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

$baseDir = "$PSScriptRoot"
ipmo $baseDir\libs\calico\calico.psm1 -Force

Write-Host "Setting environment variables if not set..."

## Cluster configuration:

# KUBE_NETWORK should be set to a regular expression that matches the HNS network(s) used for pods.
# The default, "Calico.*", is correct for Calico CNI.
Set-EnvVarIfNotSet -var "KUBE_NETWORK" -defaultValue "Calico.*"

# Set this to one of the following values:
# - "vxlan" for Calico VXLAN networking
# - "windows-bgp" for Calico BGP networking using the Windows BGP router.
# - "none" to disable the Calico CNI plugin (so that you can use another plugin).
Set-EnvVarIfNotSet -var "CALICO_NETWORKING_BACKEND" -defaultValue "vxlan"

# Set to match your Kubernetes service CIDR.
Set-EnvVarIfNotSet -var "DNS_SEARCH" -defaultValue "svc.cluster.local"

## VXLAN-specific configuration.

# The VXLAN VNI / VSID.  Must match the VXLANVNI felix configuration parameter used
# for Linux nodes.
Set-EnvVarIfNotSet -var "VXLAN_VNI" -defaultValue 4096
# Prefix used when generating MAC addresses for virtual NICs.
Set-EnvVarIfNotSet -var "VXLAN_MAC_PREFIX" -defaultValue "0E-2A"
# Network Adapter used on VXLAN, leave blank for primary NIC.
Set-EnvVarIfNotSet -var "VXLAN_ADAPTER" -defaultValue ""

## Node configuration.

# The NODENAME variable should be set to match the Kubernetes Node name of this host.
# The default uses this node's hostname (which is the same as kubelet).
#
# Note: on AWS, kubelet is often configured to use the internal domain name of the host rather than
# the simple hostname, for example "ip-172-16-101-135.us-west-2.compute.internal".
Set-EnvVarIfNotSet -var "NODENAME" -defaultValue $(hostname).ToLower()
# Similarly, CALICO_K8S_NODE_REF should be set to the Kubernetes Node name.  When using etcd,
# the Calico kube-controllers pod will clean up Calico node objects if the corresponding Kubernetes Node is
# cleaned up.
Set-EnvVarIfNotSet -var "CALICO_K8S_NODE_REF" -defaultValue $env:NODENAME

# The time out to wait for a valid IP of an interface to be assigned before initialising Calico
# after a reboot.
Set-EnvVarIfNotSet -var "STARTUP_VALID_IP_TIMEOUT" -defaultValue 90

# The IP of the node; the default will auto-detect a usable IP in most cases.
Set-EnvVarIfNotSet -var "IP" -defaultValue "autodetect"

# Felix logs to screen at info level by default.  Uncomment this line to override the log
# level.  Alternatively, (if this is commented out) the log level can be controlled via
# the FelixConfiguration resource in the datastore.
# $env:FELIX_LOGSEVERITYSCREEN = "info"
# Disable logging to file by default since the service wrapper will redirect our log to file.
Set-EnvVarIfNotSet -var "FELIX_LOGSEVERITYFILE" -defaultValue "none"
# Disable syslog logging, which is not supported on Windows.
Set-EnvVarIfNotSet -var "FELIX_LOGSEVERITYSYS" -defaultValue "none"
# confd logs to screen at info level by default.  Uncomment this line to override the log
# level.
#Set-EnvVarIfNotSet -var "BGP_LOGSEVERITYSCREEN" -defaultValue "debug"
