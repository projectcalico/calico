package utils

import (
	"net"

	"github.com/containernetworking/cni/pkg/types"
)

// Policy is a struct to hold policy config (which currently happens to also contain some K8s config)
type Policy struct {
	PolicyType              string `json:"type"`
	K8sAPIRoot              string `json:"k8s_api_root"`
	K8sAuthToken            string `json:"k8s_auth_token"`
	K8sClientCertificate    string `json:"k8s_client_certificate"`
	K8sClientKey            string `json:"k8s_client_key"`
	K8sCertificateAuthority string `json:"k8s_certificate_authority"`
	K8sUsername             string `json:"k8s_username"`
	K8sPassword             string `json:"k8s_password"`
}

// Kubernetes a K8s specific struct to hold config
type Kubernetes struct {
	Kubeconfig string `json:"kubeconfig"`
	NodeName   string `json:"node_name"`
}

// NetConf stores the common network config for Calico CNI plugin
type NetConf struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	IPAM struct {
		Name       string
		Type       string  `json:"type,omitempty"`
		Subnet     string  `json:"subnet,omitempty"`
		AssignIpv4 *string `json:"assign_ipv4"`
		AssignIpv6 *string `json:"assign_ipv6"`
	} `json:"ipam,omitempty"`
	MTU           int        `json:"mtu"`
	Hostname      string     `json:"hostname"`
	EtcdAuthority string     `json:"etcd_authority"`
	EtcdEndpoints string     `json:"etcd_endpoints"`
	Debug         bool       `json:"debug"`
	Policy        Policy     `json:"policy"`
	Kubernetes    Kubernetes `json:"kubernetes"`
}

// K8sArgs is the valid CNI_ARGS used for Kubernetes
type K8sArgs struct {
	types.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}
