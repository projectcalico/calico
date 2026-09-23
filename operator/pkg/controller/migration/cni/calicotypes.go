package cni

// CalicoConf stores the common network config for Calico CNI plugin
type CalicoConf struct {
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
	MTU                  int               `json:"mtu"`
	Nodename             string            `json:"nodename"`
	NodenameFileOptional bool              `json:"nodename_file_optional"`
	DatastoreType        string            `json:"datastore_type"`
	EtcdEndpoints        string            `json:"etcd_endpoints"`
	EtcdDiscoverySrv     string            `json:"etcd_discovery_srv"`
	LogLevel             string            `json:"log_level"`
	FeatureControl       FeatureControl    `json:"feature_control"`
	EtcdScheme           string            `json:"etcd_scheme"`
	EtcdKeyFile          string            `json:"etcd_key_file"`
	EtcdCertFile         string            `json:"etcd_cert_file"`
	EtcdCaCertFile       string            `json:"etcd_ca_cert_file"`
	ContainerSettings    ContainerSettings `json:"container_settings,omitempty"`
	IncludeDefaultRoutes bool              `json:"include_default_routes,omitempty"`
}

// ContainerSettings contains configuration options
// to be configured inside the container namespace.
type ContainerSettings struct {
	AllowIPForwarding bool `json:"allow_ip_forwarding"`
}

// FeatureControl is a struct which controls which features are enabled in Calico.
type FeatureControl struct {
	IPAddrsNoIpam bool `json:"ip_addrs_no_ipam"`
	FloatingIPs   bool `json:"floating_ips"`
}
