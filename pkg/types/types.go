// Copyright (c) 2016 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

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
}

// FeatureControl is a struct which controls which features are enabled in Calico.
type FeatureControl struct {
	IPAddrsNoIpam bool `json:"ip_addrs_no_ipam"`
	FloatingIPs   bool `json:"floating_ips"`
}

// Kubernetes a K8s specific struct to hold config
type Kubernetes struct {
	K8sAPIRoot string `json:"k8s_api_root"`
	Kubeconfig string `json:"kubeconfig"`
	NodeName   string `json:"node_name"`
}

type Args struct {
	Mesos Mesos `json:"org.apache.mesos,omitempty"`
}

type Mesos struct {
	NetworkInfo NetworkInfo `json:"network_info"`
}

type NetworkInfo struct {
	Name   string `json:"name"`
	Labels struct {
		Labels []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"labels,omitempty"`
	} `json:"labels,omitempty"`
}

// NetConf stores the common network config for Calico CNI plugin
type NetConf struct {
	CNIVersion string `json:"cniVersion,omitempty"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	IPAM       struct {
		Name       string
		Type       string   `json:"type"`
		Subnet     string   `json:"subnet"`
		AssignIpv4 *string  `json:"assign_ipv4"`
		AssignIpv6 *string  `json:"assign_ipv6"`
		IPv4Pools  []string `json:"ipv4_pools,omitempty"`
		IPv6Pools  []string `json:"ipv6_pools,omitempty"`
	} `json:"ipam,omitempty"`
	Args                 Args              `json:"args"`
	MTU                  int               `json:"mtu"`
	Nodename             string            `json:"nodename"`
	NodenameFile         string            `json:"nodename_file"`
	NodenameFileOptional bool              `json:"nodename_file_optional"`
	DatastoreType        string            `json:"datastore_type"`
	EtcdEndpoints        string            `json:"etcd_endpoints"`
	LogLevel             string            `json:"log_level"`
	Policy               Policy            `json:"policy"`
	Kubernetes           Kubernetes        `json:"kubernetes"`
	FeatureControl       FeatureControl    `json:"feature_control"`
	EtcdScheme           string            `json:"etcd_scheme"`
	EtcdKeyFile          string            `json:"etcd_key_file"`
	EtcdCertFile         string            `json:"etcd_cert_file"`
	EtcdCaCertFile       string            `json:"etcd_ca_cert_file"`
	ContainerSettings    ContainerSettings `json:"container_settings,omitempty"`
	IncludeDefaultRoutes bool              `json:"include_default_routes,omitempty"`

	// Options below here are deprecated.
	EtcdAuthority string `json:"etcd_authority"`
	Hostname      string `json:"hostname"`
}

// ContainerSettings gcontains configuration options
// to be configured inside the container namespace.
type ContainerSettings struct {
	AllowIPForwarding bool `json:"allow_ip_forwarding"`
}

// CNITestArgs is the CNI_ARGS used for test purposes.
type CNITestArgs struct {
	types.CommonArgs
	CNI_TEST_NAMESPACE types.UnmarshallableString
}

// K8sArgs is the valid CNI_ARGS used for Kubernetes
type K8sArgs struct {
	types.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}
