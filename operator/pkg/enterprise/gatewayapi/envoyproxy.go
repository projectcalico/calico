// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package gatewayapi

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/utils/ptr"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"

	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/gatewayapi"
)

const (
	// wafLogComponentWasm is the Envoy "wasm" logger component. Envoy Gateway does not
	// define a const for it (its enum omits wasm), but EnvoyProxy.Spec.Logging.Level
	// passes arbitrary component keys through to Envoy's --component-log-level arg, and
	// Envoy recognises "wasm". Setting it to info surfaces the Coraza WASM filter's
	// "AuditLog:" lines (emitted via proxywasm.LogInfo) in Envoy's application log.
	wafLogComponentWasm = envoyapi.ProxyLogComponent("wasm")

	// wafAuditLogPath is the file that Envoy's application log is redirected to via
	// --log-path, and that the l7-log-collector tails for Coraza "AuditLog:" lines
	// (WAF_AUDIT_LOG_PATH). It lives on the "access-logs" emptyDir that is already
	// mounted in both the envoy container (which writes it) and the l7-log-collector
	// (which reads it), so no extra volume or mount is needed. Envoy will not create
	// parent directories for --log-path, so this is a file directly under the existing
	// /access_logs mount, not a new subdirectory.
	wafAuditLogPath = "/access_logs/envoy.log"
)

var (
	accessLogType envoyapi.ProxyAccessLogType = "Route"

	// Owning Gateway name and namespace are exposed via pod labels set by EnvoyProxy.
	// These allow the l7-log-collector to know which Gateway it is collecting logs for
	// without needing to query the Kubernetes API.
	OwningGatewayNameEnvVar = corev1.EnvVar{
		Name: "OWNING_GATEWAY_NAME",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.labels['gateway.envoyproxy.io/owning-gateway-name']",
			},
		},
	}
	OwningGatewayNamespaceEnvVar = corev1.EnvVar{
		Name: "OWNING_GATEWAY_NAMESPACE",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.labels['gateway.envoyproxy.io/owning-gateway-namespace']",
			},
		},
	}
)

// applyWAFAndLogCollector adds the WAF HTTP filter's Envoy configuration and the
// l7-log-collector container to a rendered EnvoyProxy.
func applyWAFAndLogCollector(envoyProxy *envoyapi.EnvoyProxy, image string) {
	// The WAF HTTP filter is not supported when the envoy proxy is deployed as a DaemonSet
	// as there is no support for init containers in a DaemonSet.
	if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment != nil {
		// Tune Envoy log levels for WAF audit capture: the wasm component logs at
		// info so the Coraza filter's "AuditLog:" lines reach Envoy's application
		// log, while the default stays at warn to keep the redirected log file
		// approximately just the audit lines. A user-supplied default level (e.g.
		// for debugging) is preserved.
		if envoyProxy.Spec.Logging.Level == nil {
			envoyProxy.Spec.Logging.Level = map[envoyapi.ProxyLogComponent]envoyapi.LogLevel{}
		}
		if _, ok := envoyProxy.Spec.Logging.Level[envoyapi.LogComponentDefault]; !ok {
			envoyProxy.Spec.Logging.Level[envoyapi.LogComponentDefault] = envoyapi.LogLevelWarn
		}
		envoyProxy.Spec.Logging.Level[wafLogComponentWasm] = envoyapi.LogLevelInfo

		// Redirect Envoy's application log (where the wasm filter's "AuditLog:" lines land)
		// to a file on the "access-logs" emptyDir so the l7-log-collector can tail it (the
		// collector already mounts that volume, and can only read files under /access_logs).
		// EnvoyProxy has no native log-path field, and a Patch on the envoy container's args
		// would replace Envoy Gateway's generated args, so use ExtraArgs, which EG appends to
		// the proxy command line. func-e parses each element as a single token, so the flag
		// and value are separate elements. The operator owns --log-path whenever WAF audit
		// capture is enabled: it must match WAF_AUDIT_LOG_PATH on the l7-log-collector and
		// live on the shared access-logs volume, so set it to wafAuditLogPath, replacing any
		// value carried over from a custom base EnvoyProxy.
		envoyProxy.Spec.ExtraArgs = ensureExtraArg(envoyProxy.Spec.ExtraArgs, "--log-path", wafAuditLogPath)

		l7LogCollector := corev1.Container{
			Name:  "l7-log-collector",
			Image: image,
			Env: []corev1.EnvVar{
				{
					Name:  "LOG_LEVEL",
					Value: "info",
				},
				{
					Name:  "FELIX_DIAL_TARGET",
					Value: "/var/run/felix/nodeagent/socket",
				},
				{
					Name:  "ENVOY_ACCESS_LOG_PATH",
					Value: "/access_logs/access.log",
				},
				// WAF audit capture: file the collector tails for the wasm filter's
				// Coraza "AuditLog:" lines (Envoy's app log, redirected via --log-path).
				{
					Name:  "WAF_AUDIT_LOG_PATH",
					Value: wafAuditLogPath,
				},
				// Owning Gateway info from pod labels (set by EnvoyProxy)
				OwningGatewayNameEnvVar,
				OwningGatewayNamespaceEnvVar,
			},
			RestartPolicy: ptr.To(corev1.ContainerRestartPolicyAlways),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "access-logs",
					MountPath: "/access_logs",
				},
				{
					Name:      "felix-sync",
					MountPath: "/var/run/felix",
				},
			},
			SecurityContext: securitycontext.NewRootContext(true),
		}

		hasL7LogCollector := false
		for i, initContainer := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers {
			if initContainer.Name == l7LogCollector.Name {
				hasL7LogCollector = true
				// Handle update
				if initContainer.Image != l7LogCollector.Image {
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].Image = l7LogCollector.Image
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].Env = l7LogCollector.Env
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].VolumeMounts = l7LogCollector.VolumeMounts
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].RestartPolicy = l7LogCollector.RestartPolicy
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers[i].SecurityContext = l7LogCollector.SecurityContext
				}
			}
		}
		if !hasL7LogCollector {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.InitContainers, l7LogCollector)
		}

		accessLogsName := "access-logs"
		// Add or update Container volume mount
		l7SocketVolumeMount := corev1.VolumeMount{
			Name:      accessLogsName,
			MountPath: "/access_logs",
		}

		hasAccessLogsVolumeMount := false
		for i, volumeMount := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts {
			if volumeMount.Name == l7SocketVolumeMount.Name {
				hasAccessLogsVolumeMount = true
				if volumeMount.MountPath != l7SocketVolumeMount.MountPath {
					envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts[i] = l7SocketVolumeMount
				}
			}
		}
		if !hasAccessLogsVolumeMount {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Container.VolumeMounts, l7SocketVolumeMount)
		}

		// Add or update Pod volumes
		AccessLogsVolume := []corev1.Volume{
			{
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
				Name: accessLogsName,
			},
			{
				VolumeSource: corev1.VolumeSource{
					CSI: &corev1.CSIVolumeSource{
						Driver: "csi.tigera.io",
					},
				},
				Name: "felix-sync",
			},
		}
		hasAccessLogsVolume := false
		for i, volume := range envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes {
			for _, acVolume := range AccessLogsVolume {
				if volume.Name == acVolume.Name {
					hasAccessLogsVolume = true
					if acVolume.VolumeSource != volume.VolumeSource {
						envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes[i] = acVolume
					}
				}
			}
		}
		if !hasAccessLogsVolume {
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes = append(envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Pod.Volumes, AccessLogsVolume...)
		}

		// Configure the envoy-proxy pod's service account, used by the l7-log-collector
		// for license verification and Gateway-API reads.
		// Use EnvoyProxy patch mechanism to set serviceAccountName and automountServiceAccountToken
		serviceAccountPatch := map[string]interface{}{
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"serviceAccountName":           gatewayapi.WAFFilterName,
						"automountServiceAccountToken": true,
					},
				},
			},
		}

		// Convert patch to JSON
		patchBytes, err := json.Marshal(serviceAccountPatch)
		if err == nil {
			if envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Patch == nil {
				envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Patch = &envoyapi.KubernetesPatchSpec{}
			}
			envoyProxy.Spec.Provider.Kubernetes.EnvoyDeployment.Patch.Value = apiextenv1.JSON{Raw: patchBytes}
		}

		if envoyProxy.Spec.Telemetry != nil {
			if envoyProxy.Spec.Telemetry.AccessLog == nil {
				envoyProxy.Spec.Telemetry.AccessLog = &envoyapi.ProxyAccessLog{
					Settings: []envoyapi.ProxyAccessLogSetting{},
				}
			}
		} else {
			envoyProxy.Spec.Telemetry = &envoyapi.ProxyTelemetry{
				AccessLog: &envoyapi.ProxyAccessLog{
					Settings: []envoyapi.ProxyAccessLogSetting{},
				},
			}
		}

		envoyProxy.Spec.Telemetry.AccessLog.Settings = []envoyapi.ProxyAccessLogSetting{
			{
				Sinks: []envoyapi.ProxyAccessLogSink{
					{
						Type: envoyapi.ProxyAccessLogSinkTypeFile,
						File: &envoyapi.FileEnvoyProxyAccessLog{
							Path: "/access_logs/access.log",
						},
					},
				},
				Format: &envoyapi.ProxyAccessLogFormat{
					Type: ptr.To(envoyapi.ProxyAccessLogFormatTypeJSON),
					JSON: map[string]string{
						"reporter":                         "gateway",
						"start_time":                       "%START_TIME%",
						"duration":                         "%DURATION%",
						"response_code":                    "%RESPONSE_CODE%",
						"bytes_sent":                       "%BYTES_SENT%",
						"bytes_received":                   "%BYTES_RECEIVED%",
						"user_agent":                       "%REQ(USER-AGENT)%",
						"request_path":                     "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
						"request_method":                   "%REQ(:METHOD)%",
						"request_id":                       "%REQ(X-REQUEST-ID)%",
						"type":                             "{{.}}",
						"downstream_remote_address":        "%DOWNSTREAM_REMOTE_ADDRESS%",
						"downstream_local_address":         "%DOWNSTREAM_LOCAL_ADDRESS%",
						"downstream_direct_remote_address": "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%",
						"domain":                           "%REQ(HOST?:AUTHORITY)%",
						"upstream_host":                    "%UPSTREAM_HOST%",
						"upstream_local_address":           "%UPSTREAM_LOCAL_ADDRESS%",
						"upstream_service_time":            "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
						"route_name":                       "%ROUTE_NAME%",
					},
				},
				Type: &accessLogType,
			},
		}
	}
}

// ensureExtraArg sets "flag value" in an Envoy Gateway ExtraArgs slice (func-e parses each token as
// a separate element), replacing the value if flag is already present as an option, or inserting the
// flag/value pair if not. A bare "--" terminates option parsing, so tokens at or after it are left
// alone: the flag is matched only before "--", and a newly inserted pair goes before it. The slice is
// copied, so this never mutates a slice backing a cached EnvoyProxy object.
func ensureExtraArg(args []string, flag, value string) []string {
	// Options end at the first bare "--"; anything from there on is a non-option token.
	sep := len(args)
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	out := make([]string, 0, len(args)+2)
	for i := 0; i < sep; i++ {
		if args[i] == flag {
			out = append(out, flag, value)
			next := i + 1
			if next < sep { // drop the existing value, if any
				next++
			}
			return append(out, args[next:]...)
		}
		out = append(out, args[i])
	}
	// flag is not present as an option: insert it just before the "--" (or at the end).
	out = append(out, flag, value)
	return append(out, args[sep:]...)
}
