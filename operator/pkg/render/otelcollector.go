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

package render

// Identity of the OpenTelemetry Collector workload. These live here rather than
// in pkg/render/otelcollector because that package imports pkg/render/monitor
// (for the Prometheus federation target), so the monitor render cannot import it
// back to build the collector's ServiceMonitor. Same arrangement as the
// fluent-bit constants in logcollector.go.
const (
	OpenTelemetryCollectorName      = "otel-collector"
	OpenTelemetryCollectorNamespace = "calico-system"
	// OpenTelemetryCollectorOTLPHTTPPort is the receiver's port, shared so
	// fluent-bit's output and the collector's own Service cannot drift apart.
	OpenTelemetryCollectorOTLPHTTPPort = 4318
	OpenTelemetryCollectorMetricsPort  = "metrics"
)
