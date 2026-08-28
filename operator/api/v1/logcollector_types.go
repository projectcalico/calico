// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LogCollectorSpec defines the desired state of Tigera flow, audit, and DNS log collection.
type LogCollectorSpec struct {
	// Configuration for exporting flow, audit, and DNS logs to external storage.
	// +optional
	AdditionalStores *AdditionalLogStoreSpec `json:"additionalStores,omitempty"`

	// Configuration for importing audit logs from managed kubernetes cluster log sources.
	// +optional
	AdditionalSources *AdditionalLogSourceSpec `json:"additionalSources,omitempty"`

	// Configuration for enabling/disabling process path collection in flowlogs.
	// If Enabled, this feature sets hostPID to true in order to read process cmdline.
	// Default: Enabled
	// +optional
	// +kubebuilder:validation:Enum=Enabled;Disabled
	CollectProcessPath *CollectProcessPathOption `json:"collectProcessPath,omitempty"`

	// If running as a multi-tenant management cluster, the namespace in which
	// the management cluster's tenant services are running.
	// +optional
	MultiTenantManagementClusterNamespace string `json:"multiTenantManagementClusterNamespace,omitempty"`

	// FluentdDaemonSet configures the calico-fluent-bit DaemonSet (deprecated alias).
	//
	// Deprecated: use CalicoFluentBitDaemonSet instead. This field is retained
	// as an alias for one release during the Fluentd → Fluent Bit migration;
	// when both are set, CalicoFluentBitDaemonSet takes precedence.
	// +optional
	FluentdDaemonSet *FluentBitDaemonSet `json:"fluentdDaemonSet,omitempty"`

	// CalicoFluentBitDaemonSet configures the calico-fluent-bit DaemonSet, the
	// Fluent Bit replacement for the Fluentd DaemonSet. Pod-template override
	// semantics are unchanged from the deprecated FluentdDaemonSet field.
	// +optional
	CalicoFluentBitDaemonSet *FluentBitDaemonSet `json:"calicoFluentBitDaemonSet,omitempty"`

	// EKSLogForwarderDeployment configures the EKSLogForwarderDeployment Deployment.
	// +optional
	EKSLogForwarderDeployment *EKSLogForwarderDeployment `json:"eksLogForwarderDeployment,omitempty"`

	// OpenTelemetry configures OpenTelemetry export of logs and metrics via
	// OTLP. It is not a passthrough for OpenTelemetry Collector configuration:
	// the fields here describe what Calico Enterprise exports and where, and
	// the operator translates that into a Collector deployment.
	//
	// Unlike AdditionalStores entries (S3, Syslog, Splunk), which point at
	// external systems, that Collector is operator-managed infrastructure
	// (StatefulSet, ConfigMap, RBAC, certs) with its own lifecycle, so this
	// lives at the top level rather than under AdditionalStores.
	// +optional
	OpenTelemetry *OpenTelemetrySpec `json:"openTelemetry,omitempty"`
}

type CollectProcessPathOption string

const (
	CollectProcessPathEnable  CollectProcessPathOption = "Enabled"
	CollectProcessPathDisable CollectProcessPathOption = "Disabled"
)

// EncryptionOption specifies the traffic encryption mode when connecting to a Syslog server.
//
// One of: None, TLS
type EncryptionOption string

const (
	EncryptionNone EncryptionOption = "None"
	EncryptionTLS  EncryptionOption = "TLS"
)

type AdditionalLogStoreSpec struct {
	// If specified, enables exporting of flow, audit, and DNS logs to Amazon S3 storage.
	// +optional
	S3 *S3StoreSpec `json:"s3,omitempty"`
	// If specified, enables exporting of flow, audit, and DNS logs to syslog.
	// +optional
	Syslog *SyslogStoreSpec `json:"syslog,omitempty"`
	// If specified, enables exporting of flow, audit, and DNS logs to splunk.
	// +optional
	Splunk *SplunkStoreSpec `json:"splunk,omitempty"`
}

type AdditionalLogSourceSpec struct {
	// If specified with EKS Provider in Installation, enables fetching EKS
	// audit logs.
	// +optional
	EksCloudwatchLog *EksCloudwatchLogsSpec `json:"eksCloudwatchLog,omitempty"`
}

// HostScope determines the set of hosts that forward logs to a given store.
// +kubebuilder:default=All
// +kubebuilder:validation:Enum=All;NonClusterOnly
// +optional
type HostScope string

const (
	HostScopeAll            HostScope = "All"
	HostScopeNonClusterOnly HostScope = "NonClusterOnly"
)

// S3StoreSpec defines configuration for exporting logs to Amazon S3.
// +k8s:openapi-gen=true
type S3StoreSpec struct {
	// AWS Region of the S3 bucket
	Region string `json:"region"`

	// Name of the S3 bucket to send logs
	BucketName string `json:"bucketName"`

	// Path in the S3 bucket where to send logs
	BucketPath string `json:"bucketPath"`

	// The set of hosts that will forward their logs to this store.
	// +optional
	HostScope *HostScope `json:"hostScope,omitempty"`
}

// SyslogLogType represents the allowable log types for syslog.
// Allowable values are Audit, DNS, Flows and IDSEvents.
// * Audit corresponds to audit logs for both Kubernetes resources and Enterprise custom resources.
// * DNS corresponds to DNS logs generated by Calico node.
// * Flows corresponds to flow logs generated by Calico node.
// * IDSEvents corresponds to event logs for the intrusion detection system (anomaly detection, suspicious IPs, suspicious domains and global alerts).
// +kubebuilder:validation:Enum=Audit;DNS;Flows;IDSEvents
type SyslogLogType string

const (
	SyslogLogAudit     SyslogLogType = "Audit"
	SyslogLogDNS       SyslogLogType = "DNS"
	SyslogLogFlows     SyslogLogType = "Flows"
	SyslogLogL7        SyslogLogType = "L7"
	SyslogLogIDSEvents SyslogLogType = "IDSEvents"
)

var SyslogLogTypes []SyslogLogType = []SyslogLogType{
	SyslogLogAudit,
	SyslogLogDNS,
	SyslogLogFlows,
	SyslogLogL7,
	SyslogLogIDSEvents,
}

var SyslogLogTypesString []string = []string{
	SyslogLogAudit.String(),
	SyslogLogDNS.String(),
	SyslogLogFlows.String(),
	SyslogLogL7.String(),
	SyslogLogIDSEvents.String(),
}

func (cp SyslogLogType) String() string {
	return string(cp)
}

// SyslogStoreSpec defines configuration for exporting logs to syslog.
type SyslogStoreSpec struct {
	// Location of the syslog server. example: tcp://1.2.3.4:601
	// Only the tcp and udp schemes are supported; TLS is selected via the
	// Encryption field rather than the scheme.
	// +kubebuilder:validation:Pattern=`^(tcp|udp)://.+$`
	Endpoint string `json:"endpoint"`

	// PacketSize defines the maximum size, in bytes, of messages sent to syslog;
	// messages larger than this are truncated. When unset, the syslog output's
	// own default for the RFC5424 format the operator renders applies (2048
	// bytes). Set this only if you notice long logs being truncated.
	// +optional
	PacketSize *int32 `json:"packetSize,omitempty"`

	// If no values are provided, the list will be updated to include log types Audit, DNS and Flows.
	// Default: Audit, DNS, Flows
	LogTypes []SyslogLogType `json:"logTypes"`

	// Encryption configures traffic encryption to the Syslog server.
	// Default: None
	// +optional
	// +kubebuilder:validation:Enum=None;TLS
	Encryption EncryptionOption `json:"encryption,omitempty"`

	// The set of hosts that will forward their logs to this store.
	// +optional
	HostScope *HostScope `json:"hostScope,omitempty"`
}

// SplunkStoreSpec defines configuration for exporting logs to splunk.
type SplunkStoreSpec struct {
	// Location for splunk's http event collector end point. example `https://1.2.3.4:8088`
	Endpoint string `json:"endpoint"`

	// The set of hosts that will forward their logs to this store
	// +optional
	HostScope *HostScope `json:"hostScope,omitempty"`
}

// EksConfigSpec defines configuration for fetching EKS audit logs.
type EksCloudwatchLogsSpec struct {
	// AWS Region EKS cluster is hosted in.
	Region string `json:"region"`

	// Cloudwatch log-group name containing EKS audit logs.
	GroupName string `json:"groupName"`

	// Prefix of Cloudwatch log stream containing EKS audit logs in the log-group.
	// Default: kube-apiserver-audit-
	// +optional
	StreamPrefix string `json:"streamPrefix,omitempty"`

	// Cloudwatch audit logs fetching interval in seconds.
	// Default: 60
	// +optional
	FetchInterval int32 `json:"fetchInterval,omitempty"`
}

// LogCollectorStatus defines the observed state of Tigera flow and DNS log collection
type LogCollectorStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// LogCollector installs the components required for Tigera flow and DNS log collection. At most one instance
// of this resource is supported. It must be named "tigera-secure". When created, this installs fluent-bit on all nodes
// configured to collect Tigera log data and export it to Tigera's Elasticsearch cluster as well as any additionally configured destinations.
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'tigera-secure'",message="resource name must be 'tigera-secure'"
type LogCollector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired state for Tigera log collection.
	Spec LogCollectorSpec `json:"spec,omitempty"`
	// Most recently observed state for Tigera log collection.
	Status LogCollectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LogCollectorList contains a list of LogCollector
type LogCollectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LogCollector `json:"items"`
}

// OpenTelemetrySpec defines the desired state of the OpenTelemetry Collector.
type OpenTelemetrySpec struct {
	// Logs configures which log types are exported via OTLP.
	// +optional
	Logs *OpenTelemetryLogs `json:"logs,omitempty"`

	// Metrics configures whether Calico component metrics are exported via OTLP.
	// +optional
	Metrics *OpenTelemetryMetrics `json:"metrics,omitempty"`

	// Exporters configures the OTLP export endpoints. At least one is required,
	// and everything exported is sent to all of them.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	Exporters []OpenTelemetryExporter `json:"exporters,omitempty"`

	// OpenTelemetryCollectorStatefulSet configures the OpenTelemetry Collector StatefulSet.
	// +optional
	OpenTelemetryCollectorStatefulSet *OpenTelemetryCollectorStatefulSet `json:"openTelemetryCollectorStatefulSet,omitempty"`
}

func (s *OpenTelemetrySpec) HasLogs() bool {
	return s != nil && s.Logs != nil && len(s.Logs.Types) > 0
}

func (s *OpenTelemetrySpec) MetricsEnabled() bool {
	return s != nil && s.Metrics != nil && s.Metrics.State != nil &&
		*s.Metrics.State == OpenTelemetryMetricsEnabled
}

func (s *OpenTelemetrySpec) HasDataSources() bool {
	return s.HasLogs() || s.MetricsEnabled()
}

// Validate rejects the specs that render a config the collector refuses to start
// from. otelcol validates most of these itself, but only at boot, by which point
// the failure is an opaque crash-loop. It lives here rather than in the otel
// controller so every controller that has to decide whether the collector is
// deployable answers the question the same way.
func (s *OpenTelemetrySpec) Validate() error {
	// Every pipeline we render fans out to all exporters, so with none configured
	// each pipeline would be exporter-less.
	if len(s.Exporters) == 0 {
		return fmt.Errorf("at least one exporter must be configured in spec.openTelemetry.exporters")
	}
	// No log types and no metrics means no pipelines at all.
	if !s.HasDataSources() {
		return fmt.Errorf("at least one data source must be enabled: set spec.openTelemetry.logs.types or spec.openTelemetry.metrics.state")
	}
	// Names key the exporters in the rendered config, so duplicates would emit the
	// same mapping key twice. +listMapKey=name normally stops this at the API
	// server; this guards the case where the CRD is out of date.
	seen := make(map[string]struct{}, len(s.Exporters))
	// Header credentials reach the collector as environment variables whose names
	// are derived from the exporter and header. Two headers can only collide if
	// they differ solely by characters that sanitise to the same thing, and a
	// collision would send one backend's credential to another, so reject it.
	envNames := map[string]string{}
	for _, exp := range s.Exporters {
		if _, dup := seen[exp.Name]; dup {
			return fmt.Errorf("exporter names must be unique in spec.openTelemetry.exporters: %q is duplicated", exp.Name)
		}
		seen[exp.Name] = struct{}{}
		// The endpoint Pattern already rejects anything but https at the API server;
		// this catches a stale CRD, where the alternative is exporting telemetry and
		// its credentials in the clear.
		if !strings.HasPrefix(strings.ToLower(exp.Endpoint), "https://") {
			return fmt.Errorf("exporter %q endpoint must use https://, got %q", exp.Name, exp.Endpoint)
		}
		for _, h := range exp.AuthHeaders() {
			if h.ValueFrom.SecretKeyRef == nil || h.ValueFrom.SecretKeyRef.Name == "" || h.ValueFrom.SecretKeyRef.Key == "" {
				return fmt.Errorf("exporter %q header %q must set valueFrom.secretKeyRef.name and .key", exp.Name, h.Name)
			}
			env := HeaderEnvName(exp.Name, h.Name)
			if prev, dup := envNames[env]; dup {
				return fmt.Errorf("exporter %q header %q collides with %s once encoded for the environment; rename one of them", exp.Name, h.Name, prev)
			}
			envNames[env] = fmt.Sprintf("exporter %q header %q", exp.Name, h.Name)
		}
	}
	return nil
}

// Deployable reports whether the operator will actually run a collector for this
// LogCollector: export configured, licensed, and a valid spec. The monitor
// controller renders the collector's ServiceMonitor and the Prometheus egress
// rule that reaches it, so it has to agree with the otel controller exactly.
func (s *OpenTelemetrySpec) Deployable(featureActive bool) bool {
	return s != nil && featureActive && s.Validate() == nil
}

func init() {
	SchemeBuilder.Register(&LogCollector{}, &LogCollectorList{})
}

// OpenTelemetryLogType represents the allowable log types for OpenTelemetry export.
// +kubebuilder:validation:Enum=Audit;DNS;Flows
type OpenTelemetryLogType string

const (
	OpenTelemetryAuditLog OpenTelemetryLogType = "Audit"
	OpenTelemetryDNSLog   OpenTelemetryLogType = "DNS"
	OpenTelemetryFlowLog  OpenTelemetryLogType = "Flows"
)

// OpenTelemetryLogs configures log export.
type OpenTelemetryLogs struct {
	// Types specifies which log types to export. Supported values: Audit, DNS, Flows.
	// +optional
	Types []OpenTelemetryLogType `json:"types,omitempty"`
}

// OpenTelemetryMetricsState is the option to enable or disable metrics export.
// +kubebuilder:validation:Enum=Enabled;Disabled
type OpenTelemetryMetricsState string

const (
	OpenTelemetryMetricsEnabled  OpenTelemetryMetricsState = "Enabled"
	OpenTelemetryMetricsDisabled OpenTelemetryMetricsState = "Disabled"
)

// OpenTelemetryMetrics configures metrics export.
type OpenTelemetryMetrics struct {
	// State specifies whether Calico component metrics are scraped and exported via OTLP.
	// Default: Disabled
	// +optional
	// +kubebuilder:default=Disabled
	State *OpenTelemetryMetricsState `json:"state,omitempty"`
}

// OpenTelemetryExporterProtocol specifies the OTLP transport protocol.
// +kubebuilder:validation:Enum=grpc;http
type OpenTelemetryExporterProtocol string

const (
	OpenTelemetryProtocolGRPC OpenTelemetryExporterProtocol = "grpc"
	OpenTelemetryProtocolHTTP OpenTelemetryExporterProtocol = "http"
)

// OpenTelemetryExporter defines an OTLP export endpoint.
type OpenTelemetryExporter struct {
	// Name uniquely identifies this exporter. Must be a DNS label.
	// +required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Endpoint is the OTLP endpoint URL. Must be https: telemetry and its
	// credentials are never sent in the clear.
	// +required
	// +kubebuilder:validation:Pattern=`^[Hh][Tt][Tt][Pp][Ss]://.+$`
	Endpoint string `json:"endpoint"`

	// Protocol specifies the OTLP transport protocol. Default: grpc.
	// +optional
	// +kubebuilder:default=grpc
	Protocol OpenTelemetryExporterProtocol `json:"protocol,omitempty"`

	// TLS configures transport security for this exporter. When omitted, the
	// endpoint is verified against the system roots.
	// +optional
	TLS *OpenTelemetryExporterTLS `json:"tls,omitempty"`

	// Auth configures how requests to this exporter are authenticated.
	// +optional
	Auth *OpenTelemetryExporterAuth `json:"auth,omitempty"`
}

// OpenTelemetryExporterTLS configures transport security for a single exporter.
type OpenTelemetryExporterTLS struct {
	// CAConfigMapName names a ConfigMap in the tigera-operator namespace holding
	// the CA that signs this exporter's serving certificate, under a tls.crt key.
	// When set, this CA alone is trusted for this exporter; the system roots are not.
	// +optional
	CAConfigMapName string `json:"caConfigMapName,omitempty"`

	// ClientCertSecretName names a Secret in the tigera-operator namespace holding
	// the client keypair to present to this exporter, under tls.crt and tls.key.
	// Setting it turns on mutual TLS for this exporter.
	// +optional
	ClientCertSecretName string `json:"clientCertSecretName,omitempty"`
}

// OpenTelemetryExporterAuth configures request authentication for a single exporter.
type OpenTelemetryExporterAuth struct {
	// Headers are attached to every request to this exporter. Values are read from
	// Secrets rather than set inline.
	// +optional
	// +listType=map
	// +listMapKey=name
	Headers []OpenTelemetryExporterHeader `json:"headers,omitempty"`
}

// OpenTelemetryExporterHeader is a single request header and where its value comes from.
type OpenTelemetryExporterHeader struct {
	// Name is the header name, for example Authorization or DD-API-KEY.
	// +required
	Name string `json:"name"`

	// ValueFrom selects the Secret key holding this header's value. The value is
	// sent verbatim, so a bearer token must include the "Bearer " prefix in the
	// Secret: "Bearer eyJhbGci...", not "eyJhbGci...".
	// +required
	ValueFrom OpenTelemetryHeaderValueSource `json:"valueFrom"`
}

// OpenTelemetryHeaderValueSource selects where a header value is read from.
type OpenTelemetryHeaderValueSource struct {
	// SecretKeyRef selects a key of a Secret in the tigera-operator namespace.
	// +required
	SecretKeyRef *corev1.SecretKeySelector `json:"secretKeyRef"`
}

// CAConfigMap returns the user-supplied CA ConfigMap for this exporter, if any.
func (e OpenTelemetryExporter) CAConfigMap() string {
	if e.TLS == nil {
		return ""
	}
	return e.TLS.CAConfigMapName
}

// ClientCertSecret returns the client keypair Secret for this exporter, if any.
func (e OpenTelemetryExporter) ClientCertSecret() string {
	if e.TLS == nil {
		return ""
	}
	return e.TLS.ClientCertSecretName
}

// AuthHeaders returns the configured auth headers for this exporter, if any.
func (e OpenTelemetryExporter) AuthHeaders() []OpenTelemetryExporterHeader {
	if e.Auth == nil {
		return nil
	}
	return e.Auth.Headers
}

// HeaderEnvName is the environment variable a header credential is passed to the
// collector in, and the key it is stored under. It lives here so validation and
// rendering derive it the same way; a mismatch would leave the collector
// referencing a variable that was never set.
func HeaderEnvName(exporter, header string) string {
	return "OTEL_EXPORTER_" + envSafe(exporter) + "_" + envSafe(header)
}

// envSafe maps a name onto the characters an environment variable allows.
// Exporter names are restricted to a DNS label, so they cannot collide here;
// header names are not, which is why Validate rejects any pair that does.
func envSafe(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// OpenTelemetryCollectorStatefulSet is the configuration for the OpenTelemetry Collector StatefulSet.
type OpenTelemetryCollectorStatefulSet struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the StatefulSet.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the specification of the OpenTelemetry Collector StatefulSet.
	// +optional
	Spec *OpenTelemetryCollectorStatefulSetSpec `json:"spec,omitempty"`
}

// OpenTelemetryCollectorStatefulSetSpec defines configuration for the OpenTelemetry Collector StatefulSet.
type OpenTelemetryCollectorStatefulSetSpec struct {
	// MinReadySeconds is the minimum number of seconds for which a newly created StatefulSet pod should
	// be ready without any of its container crashing, for it to be considered available.
	// If specified, this overrides any minReadySeconds value that may be set on the OpenTelemetry Collector StatefulSet.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for minReadySeconds.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	MinReadySeconds *int32 `json:"minReadySeconds,omitempty"`

	// Template describes the OpenTelemetry Collector StatefulSet pod that will be created.
	// +optional
	Template *OpenTelemetryCollectorStatefulSetPodTemplateSpec `json:"template,omitempty"`
}

// OpenTelemetryCollectorStatefulSetPodTemplateSpec is the OpenTelemetry Collector StatefulSet's PodTemplateSpec.
type OpenTelemetryCollectorStatefulSetPodTemplateSpec struct {
	// Metadata is a subset of a Kubernetes object's metadata that is added to the pod's metadata.
	// +optional
	Metadata *Metadata `json:"metadata,omitempty"`
	// Spec is the OpenTelemetry Collector StatefulSet's PodSpec.
	// +optional
	Spec *OpenTelemetryCollectorStatefulSetPodSpec `json:"spec,omitempty"`
}

// OpenTelemetryCollectorStatefulSetPodSpec is the OpenTelemetry Collector StatefulSet's PodSpec.
type OpenTelemetryCollectorStatefulSetPodSpec struct {
	// Affinity is a group of affinity scheduling rules for the OpenTelemetry Collector pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// Containers is a list of OpenTelemetry Collector containers.
	// If specified, this overrides the specified OpenTelemetry Collector StatefulSet containers.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default values for its containers.
	// +optional
	Containers []OpenTelemetryCollectorStatefulSetContainer `json:"containers,omitempty"`
	// NodeSelector gives more control over the nodes where the OpenTelemetry Collector pods will run on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// TopologySpreadConstraints describes how a group of pods ought to spread across topology
	// domains. Scheduler will schedule pods in a way which abides by the constraints.
	// All topologySpreadConstraints are ANDed.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Tolerations is the OpenTelemetry Collector pod's tolerations.
	// If specified, this overrides any tolerations that may be set on the OpenTelemetry Collector StatefulSet.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
	// PriorityClassName allows to specify a PriorityClass resource to be used.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// OpenTelemetryCollectorStatefulSetContainer is an OpenTelemetry Collector StatefulSet container.
type OpenTelemetryCollectorStatefulSetContainer struct {
	// Name is an enum which identifies the OpenTelemetry Collector StatefulSet container by name.
	// Supported values are: otel-collector
	// +kubebuilder:validation:Enum=otel-collector
	Name string `json:"name"`

	// Resources allows customization of limits and requests for compute resources such as cpu and memory.
	// If specified, this overrides the named OpenTelemetry Collector StatefulSet container's resources.
	// If omitted, the OpenTelemetry Collector StatefulSet will use its default value for this container's resources.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// ReadinessProbe allows customization of the readiness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	ReadinessProbe *ProbeOverride `json:"readinessProbe,omitempty"`

	// LivenessProbe allows customization of the liveness probe timing parameters.
	// The probe handler is set by the operator and cannot be overridden.
	// +optional
	LivenessProbe *ProbeOverride `json:"livenessProbe,omitempty"`
}
