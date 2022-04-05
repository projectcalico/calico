$baseDir = "$PSScriptRoot"
ipmo $baseDir\libs\calico\calico.psm1

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
Set-EnvVarIfNotSet -var "K8S_SERVICE_CIDR" -defaultValue "<your service cidr>"
Set-EnvVarIfNotSet -var "DNS_NAME_SERVERS" -defaultValue "<your dns server ips>"
Set-EnvVarIfNotSet -var "DNS_SEARCH" -defaultValue "svc.cluster.local"

## Datastore configuration:

# Set this to "kubernetes" to use the kubernetes datastore, or "etcdv3" for etcd.
Set-EnvVarIfNotSet -var "CALICO_DATASTORE_TYPE" -defaultValue "<your datastore type>"

# Set KUBECONFIG to the path of your kubeconfig file.
Set-EnvVarIfNotSet -var "KUBECONFIG" -defaultValue "$PSScriptRoot\calico-kube-config"

# For the "etcdv3" datastore only: set ETCD_ENDPOINTS, format: "http://<host>:<port>,..."
Set-EnvVarIfNotSet -var "ETCD_ENDPOINTS" -defaultValue "<your etcd endpoints>"
# For etcd over TLS, set these lines to point to your keys/certs:
Set-EnvVarIfNotSet -var "ETCD_KEY_FILE" -defaultValue "<your etcd key>"
Set-EnvVarIfNotSet -var "ETCD_CERT_FILE" -defaultValue "<your etcd cert>"
Set-EnvVarIfNotSet -var "ETCD_CA_CERT_FILE" -defaultValue "<your etcd ca cert>"

## CNI configuration, only used for the "vxlan" networking backends.

# Place to install the CNI plugin to.  Should match kubelet's --cni-bin-dir.
Set-EnvVarIfNotSet -var "CNI_BIN_DIR" -defaultValue "c:\k\cni"
# Place to install the CNI config to.  Should be located in kubelet's --cni-conf-dir.
Set-EnvVarIfNotSet -var "CNI_CONF_DIR" -defaultValue "c:\k\cni\config"

if (Get-IsContainerdRunning)
{
    Set-EnvVarIfNotSet -var "CNI_BIN_DIR" -defaultValue (Get-ContainerdCniBinDir)
    Set-EnvVarIfNotSet -var "CNI_CONF_DIR" -defaultValue (Get-ContainerdCniConfDir)
}

Set-EnvVarIfNotSet -var "CNI_CONF_FILENAME" -defaultValue "10-calico.conf"
# IPAM type to use with Calico's CNI plugin.  One of "calico-ipam" or "host-local".
Set-EnvVarIfNotSet -var "CNI_IPAM_TYPE" -defaultValue "calico-ipam"

## VXLAN-specific configuration.

# The VXLAN VNI / VSID.  Must match the VXLANVNI felix configuration parameter used
# for Linux nodes.
Set-EnvVarIfNotSet -var "VXLAN_VNI" -defaultValue 4096
# Prefix used when generating MAC addresses for virtual NICs.
$env:VXLAN_MAC_PREFIX = "0E-2A"
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

## Logging.

Set-EnvVarIfNotSet -var "CALICO_LOG_DIR" -defaultValue "$PSScriptRoot\logs"

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
