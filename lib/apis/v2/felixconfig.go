// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindFelixConfiguration     = "FelixConfiguration"
	KindFelixConfigurationList = "FelixConfigurationList"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Felix Configuration contains the configuration for Felix.
type FelixConfiguration struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the FelixConfiguration.
	Spec FelixConfigurationSpec `json:"spec,omitempty"`
}

// TODO: Add validation on LogSeverityScreen, LogSeveritySys, LogSeverityFile, DatastoreType,
// DefaultEndpointToHostAction, IptablesFilterAllowAction, IptablesMangleAllowAction,
// ChainInsertModefor valid values.
// FelixConfigurationSpec contains the values of the Felix configuration.
type FelixConfigurationSpec struct {
	UseInternalDataplaneDriver *bool  `json:"useInternalDataplaneDriver,omitempty"`
	DataplaneDriver            string `json:"dataplaneDriver,omitempty"`

	Ipv6Support    *bool `json:"ipv6Support,omitempty"`
	IgnoreLooseRPF *bool `json:"ignoreLooseRPF,omitempty"`

	// RouterefreshInterval is the period, in seconds, at which Felix re-checks the routes
	// in the dataplane to ensure that no other process has accidentally broken Calico’s rules.
	// Set to 0 to disable route refresh. [Default: 90]
	RouteRefreshIntervalSecs *int `json:"routeRefreshIntervalSecs,omitempty" confignamev1:"RouteRefreshInterval"`
	// IptablesRefreshInterval is the period, in seconds, at which Felix re-checks the IP sets
	// in the dataplane to ensure that no other process has accidentally broken Calico’s rules.
	// Set to 0 to disable IP sets refresh. Note: the default for this value is lower than the
	// other refresh intervals as a workaround for a Linux kernel bug that was fixed in kernel
	// version 4.11. If you are using v4.11 or greater you may want to set this to, a higher value
	// to reduce Felix CPU usage. [Default: 10]
	IptablesRefreshIntervalSecs *int `json:"iptablesRefreshIntervalSecs,omitempty" confignamev1:"IptablesRefreshInterval"`
	// IptablesPostWriteCheckIntervalSecs is the period, in seconds, after Felix has done a write
	// to the dataplane that it schedules an extra read back in order to check the write was not
	// clobbered by another process. This should only occur if another application on the system
	// doesn’t respect the iptables lock. [Default: 1]
	IptablesPostWriteCheckIntervalSecs *int `json:"iptablesPostWriteCheckIntervalSecs,omitempty"`
	// IptablesLockFilePath is the location of the iptables lock file. You may need to change this
	// if the lock file is not in its standard location (for example if you have mapped it into Felix’s
	// container at a different path). [Default: /run/xtables.lock]
	IptablesLockFilePath string `json:"iptablesLockFilePath,omitempty"`
	// IptablesLockTimeoutSecs is the time, in seconds, that Felix will wait for the iptables lock,
	// or 0, to disable. To use this feature, Felix must share the iptables lock file with all other
	// processes that also take the lock. When running Felix inside a container, this requires the
	// /run directory of the host to be mounted into the calico/node or calico/felix container.
	// [Default: 0 disabled]
	IptablesLockTimeoutSecs *int `json:"iptablesLockTimeoutSecs,omitempty"`
	// IptablesLockProbeIntervalMillis is the time, in milliseconds, that Felix will wait between
	// attempts to acquire the iptables lock if it is not available. Lower values make Felix more
	// responsive when the lock is contended, but use more CPU. [Default: 50]
	IptablesLockProbeIntervalMillis *int `json:"iptablesLockProbeIntervalMillis,omitempty"`
	// IpsetsRefreshIntervalSecs is the period, in seconds, at which Felix re-checks all iptables
	// state to ensure that no other process has accidentally broken Calico’s rules. Set to 0 to
	// disable iptables refresh. [Default: 90]
	IpsetsRefreshIntervalSecs *int `json:"ipsetsRefreshIntervalSecs,omitempty" confignamev1:"IpsetsRefreshInterval"`
	MaxIpsetSize              *int `json:"maxIpsetSize,omitempty"`

	NetlinkTimeoutSecs *int `json:"netlinkTimeoutSecs,omitempty"`

	// MetadataAddr is the IP address or domain name of the server that can answer VM queries for
	// cloud-init metadata. In OpenStack, this corresponds to the machine running nova-api (or in
	// Ubuntu, nova-api-metadata). A value of none (case insensitive) means that Felix should not
	// set up any NAT rule for the metadata path. [Default: 127.0.0.1]
	MetadataAddr string `json:"metadataAddr,omitempty"`
	// MetadataPort is the port of the metadata server. This, combined with global.MetadataAddr (if
	// not ‘None’), is used to set up a NAT rule, from 169.254.169.254:80 to MetadataAddr:MetadataPort.
	// In most cases this should not need to be changed [Default: 8775].
	MetadataPort *int `json:"metadataPort,omitempty"`

	// InterfacePrefix is the interface name prefix that identifies workload endpoints and so distinguishes
	// them from host endpoint interfaces. Note: in environments other than bare metal, the orchestrators
	// configure this appropriately. For example our Kubernetes and Docker integrations set the ‘cali’ value,
	// and our OpenStack integration sets the ‘tap’ value. [Default: cali]
	InterfacePrefix string `json:"interfacePrefix,omitempty"`

	// ChainInsertMode controls whether Felix hooks the kernel’s top-level iptables chains by inserting a rule
	// at the top of the chain or by appending a rule at the bottom. insert is the safe default since it prevents
	// Calico’s rules from being bypassed. If you switch to append mode, be sure that the other rules in the chains
	// signal acceptance by falling through to the Calico rules, otherwise the Calico policy will be bypassed.
	// [Default: insert]
	ChainInsertMode string `json:"chainInstertMode,omitempty"`
	// DefaultEndpointToHostAction controls what happens to traffic that goes from a workload endpoint to the host
	// itself (after the traffic hits the endpoint egress policy). By default Calico blocks traffic from workload
	// endpoints to the host itself with an iptables “DROP” action. If you want to allow some or all traffic from
	// endpoint to host, set this parameter to RETURN or ACCEPT. Use RETURN if you have your own rules in the iptables
	// “INPUT” chain; Calico will insert its rules at the top of that chain, then “RETURN” packets to the “INPUT” chain
	// once it has completed processing workload endpoint egress policy. Use ACCEPT to unconditionally accept packets
	// from workloads after processing workload endpoint egress policy. [Default: DROP]
	DefaultEndpointToHostAction string `json:"defaultEndpointToHostAction,omitempty"`
	IptablesFilterAllowAction   string `json:"iptablesFilterAllowAction,omitempty"`
	IptablesMangleAllowAction   string `json:"iptablesMangleAllowAction,omitempty"`
	// LogPrefix is the log prefix that Felix uses when rendering LOG rules. [Default: calico-packet]
	LogPrefix string `json:"logPrefix,omitempty"`

	// LogFilePath is the full path to the Felix log. Set to none to disable file logging. [Default: /var/log/calico/felix.log]
	LogFilePath string `json:"logFilePath,omitempty"`

	// LogSeverityFile is the log severity above which logs are sent to the log file. [Default: INFO]
	LogSeverityFile string `json:"logSeverityFile,omitempty"`
	// LogSeverityScreen is the log severity above which logs are sent to the stdout. [Default: INFO]
	LogSeverityScreen string `json:"logSeverityScreen,omitempty"`
	// LogSeveritySys is the log severity above which logs are sent to the syslog. Set to NONE for no logging to syslog.
	// [Default: INFO]
	LogSeveritySys string `json:"logSeveritySys,omitempty"`

	IpInIpEnabled *bool `json:"ipInIpEnabled,omitempty"`
	// IpInIpMTU is the MTU to set on the tunnel device. See Configuring MTU [Default: 1440]
	IpInIpMtu *int `json:"ipInIpMtu,omitempty"`

	// ReportingIntervalSecs is the interval at which Felix reports its status into the datastore or 0 to disable.
	// Must be non-zero in OpenStack deployments. [Default: 30]
	ReportingIntervalSecs *int `json:"reportingIntervalSecs,omitempty"`
	// ReportingTTLSecs is the time-to-live setting for process-wide status reports. [Default: 90]
	ReportingTTLSecs *int `json:"reportingTTLSecs,omitempty"`

	EndpointReportingEnabled   *bool `json:"endpointReportingEnabled,omitempty"`
	EndpointReportingDelaySecs *int  `json:"endpointReportingDelaySecs,omitempty"`

	// IptablesMarkMask is the mask that Felix selects its IPTables Mark bits from. Should be a 32 bit hexadecimal
	// number with at least 8 bits set, none of which clash with any other mark bits in use on the system.
	// [Default: 0xff000000]
	IptablesMarkMask *uint32 `json:"iptablesMarkMask,omitempty"`

	DisableConntrackInvalidCheck *bool `json:"disableConntrackInvalidCheck,omitempty"`

	HealthEnabled *bool `json:"healthEnabled,omitempty"`
	HealthPort    *int  `json:"healthPort,omitempty"`
	// PrometheusMetricsEnabled enables the experimental Prometheus metrics server in Felix if set to true. [Default: false]
	PrometheusMetricsEnabled *bool `json:"prometheusMetricsEnabled,omitempty"`
	// PrometheusMetricsPort is the TCP port that the experimental Prometheus metrics server should bind to. [Default:9091]
	PrometheusMetricsPort *int `json:"prometheusMetricsPort,omitempty"`
	// PrometheusGoMetricsEnabled disables Go runtime metrics collection, which the Prometheus client does by default, when
	// set to false. This reduces the number of metrics reported, reducing Prometheus load. [Default: true]
	PrometheusGoMetricsEnabled *bool `json:"prometheusGoMetricsEnabled,omitempty"`
	// PrometheusProcessMetricsEnabled disables process metrics collection, which the Prometheus client does by default, when
	// set to false. This reduces the number of metrics reported, reducing Prometheus load. [Default: true]
	PrometheusProcessMetricsEnabled *bool `json:"prometheusProcessMetricsEnabled,omitempty"`

	// FailsafeInboundHostPorts is a comma-delimited list of UDP/TCP ports that Felix will allow incoming traffic to host endpoints
	// on irrespective of the security policy. This is useful to avoid accidently cutting off a host with incorrect configuration. Each
	// port should be specified as tcp:<port-number> or udp:<port-number>. For back-compatibility, if the protocol is not specified, it
	// defaults to “tcp”. To disable all inbound host ports, use the value none. The default value allows ssh access and DHCP.
	// [Default: tcp:22, udp:68]
	FailsafeInboundHostPorts *[]ProtoPort `json:"failsafeInboundHostPorts,omitempty"`
	// FailsafeOutboundHostPorts is a comma-delimited list of UDP/TCP ports that Felix will allow outgoing traffic from host endpoints to
	// irrespective of the security policy. This is useful to avoid accidently cutting off a host with incorrect configuration. Each port
	// should be specified as tcp:<port-number> or udp:<port-number>. For back-compatibility, if the protocol is not specified, it defaults
	// to “tcp”. To disable all outbound host ports, use the value none. The default value opens etcd’s standard ports to ensure that Felix
	// does not get cut off from etcd as well as allowing DHCP and DNS. [Default: tcp:2379, tcp:2380, tcp:4001, tcp:7001, udp:53, udp:67]
	FailsafeOutboundHostPorts *[]ProtoPort `json:"failsafeOutboundHostPorts,omitempty"`

	// UsageReportingEnabled reports anonymous Calico version number and cluster size to projectcalico.org. Logs warnings returned by the usage
	// server. For example, if a significant security vulnerability has been discovered in the version of Calico being used. [Default: true]
	UsageReportingEnabled *bool `json:"usageReportingEnabled,omitempty"`

	DebugMemoryProfilePath              string `json:"debugMemoryProfilePath,omitempty"`
	DebugDisableLogDropping             *bool  `json:"debugDisableLogDropping,omitempty"`
	DebugSimulateCalcGraphHangAfterSecs *int   `json:"debugSimulateCalcGraphHangAfterSecs,omitempty" confignamev1:"DebugSimulateCalcGraphHangAfter"`
	DebugSimulateDataplaneHangAfterSecs *int   `json:"debugSimulateDataplaneHangAfterSecs,omitempty" confignamev1:"DebugSimualteDataplaneHangAfter"`
}

type ProtoPort struct {
	Protocol string
	Port     uint16
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FelixConfigurationList contains a list of FelixConfiguration resources.
type FelixConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []FelixConfiguration `json:"items"`
}

// New FelixConfiguration creates a new (zeroed) FelixConfiguration struct with the TypeMetadata
// initialized to the current version.
func NewFelixConfiguration() *FelixConfiguration {
	return &FelixConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindFelixConfiguration,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// NewFelixConfigurationList creates a new 9zeroed) FelixConfigurationList struct with the TypeMetadata
// initialized to the current version.
func NewFelixConfigurationList() *FelixConfigurationList {
	return &FelixConfigurationList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindFelixConfigurationList,
			APIVersion: GroupVersionCurrent,
		},
	}
}
