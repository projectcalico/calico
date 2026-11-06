// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package cluster

import (
	"fmt"

	"sigs.k8s.io/yaml"
)

// sanitizeDiagnosticResources exports only diagnostic fields. Workload arguments,
// inline environment variables, annotations and arbitrary resource data can contain credentials.
func sanitizeDiagnosticResources(data []byte) ([]byte, error) {
	var object map[string]any
	if err := yaml.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("invalid resource YAML")
	}
	if object == nil {
		return nil, fmt.Errorf("empty resource YAML")
	}
	return yaml.Marshal(diagnosticResource(object))
}

func diagnosticResource(in map[string]any) map[string]any {
	out := diagnosticFields(in, "apiVersion", "kind")
	if meta, ok := in["metadata"].(map[string]any); ok {
		out["metadata"] = diagnosticFields(meta, "name", "namespace", "uid", "resourceVersion", "creationTimestamp", "generation")
	}
	if items, ok := in["items"].([]any); ok {
		safe := make([]any, 0, len(items))
		for _, item := range items {
			if obj, ok := item.(map[string]any); ok {
				safe = append(safe, diagnosticResource(obj))
			}
		}
		out["items"] = safe
	}
	if spec, ok := in["spec"].(map[string]any); ok {
		out["spec"] = diagnosticSpec(spec)
	}
	if status, ok := in["status"].(map[string]any); ok {
		out["status"] = diagnosticFields(status, "phase", "hostIP", "podIP", "replicas", "readyReplicas", "availableReplicas", "observedGeneration")
	}
	return out
}

func diagnosticSpec(in map[string]any) map[string]any {
	out := diagnosticFields(in, "nodeName", "serviceAccountName", "hostNetwork", "dnsPolicy", "replicas", "restartPolicy", "schedulerName")
	// Handle Pods, controllers with Pod templates and CronJob job templates.
	for _, key := range []string{"template", "jobTemplate"} {
		if template, ok := in[key].(map[string]any); ok {
			out[key] = diagnosticResource(template)
		}
	}
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		if containers, ok := in[key].([]any); ok {
			safe := make([]any, 0, len(containers))
			for _, container := range containers {
				if c, ok := container.(map[string]any); ok {
					safe = append(safe, diagnosticFields(c, "name", "image", "ports", "resources", "imagePullPolicy"))
				}
			}
			out[key] = safe
		}
	}
	return out
}

func diagnosticFields(in map[string]any, fields ...string) map[string]any {
	out := make(map[string]any)
	for _, key := range fields {
		if value, ok := in[key]; ok {
			out[key] = value
		}
	}
	return out
}

// Limit workload filtering to resource types that may embed executable Pod specs or arbitrary configuration.
func diagnosticSanitizer(resource string) func([]byte) ([]byte, error) {
	switch resource {
	case "pods", "daemonsets", "deployments", "statefulsets", "jobs", "cronjobs", "configmaps":
		return sanitizeDiagnosticResources
	default:
		return nil
	}
}
