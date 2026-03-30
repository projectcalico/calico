// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

// Package jsonbench benchmarks encoding/json v1 vs v2 using real Calico types.
//
// Run with:
//
//	GOEXPERIMENT=jsonv2 go test -bench=. -benchmem ./lib/std/jsonbench/
package jsonbench

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"testing"
	"time"
)

// ---- Realistic test data modeled on Calico types ----

// Modeled on apiv3.Rule + EntityRule (policy_common.go).
// This is on the hot path: every policy evaluation involves rules.
type rule struct {
	Action      string       `json:"action"`
	IPVersion   *int         `json:"ipVersion,omitempty"`
	Protocol    *string      `json:"protocol,omitempty"`
	Source      entityRule   `json:"source,omitzero"`
	Destination entityRule   `json:"destination,omitzero"`
	HTTP        *httpMatch   `json:"http,omitempty"`
	Metadata    *ruleMetadata `json:"metadata,omitempty"`
}

type entityRule struct {
	Nets              []string `json:"nets,omitempty"`
	Selector          string   `json:"selector,omitempty"`
	NamespaceSelector string   `json:"namespaceSelector,omitempty"`
	Ports             []string `json:"ports,omitempty"`
	NotNets           []string `json:"notNets,omitempty"`
	NotSelector       string   `json:"notSelector,omitempty"`
	NotPorts          []string `json:"notPorts,omitempty"`
}

type httpMatch struct {
	Methods []string `json:"methods,omitempty"`
}

type ruleMetadata struct {
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Modeled on apiv3.GlobalNetworkPolicySpec.
type policySpec struct {
	Order           *float64 `json:"order,omitempty"`
	Ingress         []rule   `json:"ingress,omitempty"`
	Egress          []rule   `json:"egress,omitempty"`
	Selector        string   `json:"selector,omitempty"`
	Types           []string `json:"types,omitempty"`
	DoNotTrack      bool     `json:"doNotTrack,omitempty"`
	PreDNAT         bool     `json:"preDNAT,omitempty"`
	ApplyOnForward  bool     `json:"applyOnForward,omitempty"`
}

type policyResource struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   objectMeta        `json:"metadata"`
	Spec       policySpec        `json:"spec"`
}

type objectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Generation  int64             `json:"generation,omitempty"`
}

// Modeled on a subset of FelixConfigurationSpec (~30 representative fields
// out of 100+). Heavy pointer usage, mixed types.
type felixConfigSpec struct {
	UseInternalDataplaneDriver     *bool   `json:"useInternalDataplaneDriver,omitempty"`
	DataplaneDriver                string  `json:"dataplaneDriver,omitempty"`
	IPv6Support                    *bool   `json:"ipv6Support,omitempty"`
	RouteRefreshInterval           *string `json:"routeRefreshInterval,omitempty"`
	IptablesRefreshInterval        *string `json:"iptablesRefreshInterval,omitempty"`
	IptablesBackend                *string `json:"iptablesBackend,omitempty"`
	FeatureDetectOverride          string  `json:"featureDetectOverride,omitempty"`
	FeatureGates                   string  `json:"featureGates,omitempty"`
	MaxIpsetSize                   *int    `json:"maxIpsetSize,omitempty"`
	BPFEnabled                     *bool   `json:"bpfEnabled,omitempty"`
	BPFLogLevel                    string  `json:"bpfLogLevel,omitempty"`
	BPFDataIfacePattern            string  `json:"bpfDataIfacePattern,omitempty"`
	BPFConnectTimeLoadBalancing    *string `json:"bpfConnectTimeLoadBalancing,omitempty"`
	BPFExternalServiceMode         string  `json:"bpfExternalServiceMode,omitempty"`
	BPFMapSizeConntrack            *int    `json:"bpfMapSizeConntrack,omitempty"`
	BPFMapSizeNATFrontend          *int    `json:"bpfMapSizeNATFrontend,omitempty"`
	BPFMapSizeNATBackend           *int    `json:"bpfMapSizeNATBackend,omitempty"`
	DefaultEndpointToHostAction    string  `json:"defaultEndpointToHostAction,omitempty"`
	IptablesFilterAllowAction      string  `json:"iptablesFilterAllowAction,omitempty"`
	IptablesMangleAllowAction      string  `json:"iptablesMangleAllowAction,omitempty"`
	LogSeverityScreen              string  `json:"logSeverityScreen,omitempty"`
	LogSeverityFile                string  `json:"logSeverityFile,omitempty"`
	LogSeveritySys                 string  `json:"logSeveritySys,omitempty"`
	VXLANEnabled                   *bool   `json:"vxlanEnabled,omitempty"`
	VXLANVNI                       *int    `json:"vxlanVNI,omitempty"`
	VXLANPort                      *int    `json:"vxlanPort,omitempty"`
	AllowVXLANPacketsFromWorkloads *bool   `json:"allowVXLANPacketsFromWorkloads,omitempty"`
	AllowIPIPPacketsFromWorkloads  *bool   `json:"allowIPIPPacketsFromWorkloads,omitempty"`
	TyphaAddr                      string  `json:"typhaAddr,omitempty"`
	TyphaReadTimeout               *string `json:"typhaReadTimeout,omitempty"`
	TyphaWriteTimeout              *string `json:"typhaWriteTimeout,omitempty"`
}

// Modeled on typha/pkg/syncproto.SerializedUpdate — the Typha-Felix
// wire protocol. High frequency: thousands per sync.
type serializedUpdate struct {
	Key        string `json:"key"`
	Value      []byte `json:"value"`
	Revision   any    `json:"revision"`
	TTL        int64  `json:"ttl"`
	UpdateType int    `json:"updateType"`
}

// Modeled on Kubernetes-style labels map — the most common map type.
type labeledObject struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

// ---- Test data constructors ----

func ptr[T any](v T) *T { return &v }

func makePolicy() policyResource {
	order := float64(100)
	ipv4 := 4
	tcp := "TCP"
	return policyResource{
		APIVersion: "projectcalico.org/v3",
		Kind:       "GlobalNetworkPolicy",
		Metadata: objectMeta{
			Name: "allow-web-traffic",
			Labels: map[string]string{
				"app":                          "web",
				"env":                          "production",
				"projectcalico.org/tier":       "default",
				"projectcalico.org/managed-by": "kubectl",
			},
			Annotations: map[string]string{
				"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"projectcalico.org/v3","kind":"GlobalNetworkPolicy"}`,
			},
			Generation: 3,
		},
		Spec: policySpec{
			Order:    &order,
			Selector: "app == 'web' && env == 'production'",
			Types:    []string{"Ingress", "Egress"},
			Ingress: []rule{
				{
					Action:    "Allow",
					IPVersion: &ipv4,
					Protocol:  &tcp,
					Source: entityRule{
						Selector: "role == 'frontend'",
						Nets:     []string{"10.0.0.0/8", "172.16.0.0/12"},
					},
					Destination: entityRule{
						Ports: []string{"80", "443", "8080:8090"},
					},
				},
				{
					Action:   "Allow",
					Protocol: &tcp,
					Source: entityRule{
						NamespaceSelector: "name == 'monitoring'",
						Selector:          "app == 'prometheus'",
					},
					Destination: entityRule{
						Ports: []string{"9090"},
					},
				},
				{
					Action: "Deny",
				},
			},
			Egress: []rule{
				{
					Action: "Allow",
					Destination: entityRule{
						Nets: []string{"0.0.0.0/0"},
					},
				},
			},
		},
	}
}

func makeFelixConfig() felixConfigSpec {
	return felixConfigSpec{
		UseInternalDataplaneDriver:     ptr(true),
		IPv6Support:                    ptr(false),
		RouteRefreshInterval:           ptr("90s"),
		IptablesRefreshInterval:        ptr("10s"),
		IptablesBackend:                ptr("Auto"),
		FeatureDetectOverride:          "SNATFullyRandom=true,MASQFullyRandom=false",
		MaxIpsetSize:                   ptr(1048576),
		BPFEnabled:                     ptr(true),
		BPFLogLevel:                    "Off",
		BPFDataIfacePattern:            "^((en|wl|ww|sl|ib)[opsx].*|(eth|wlan|wwan).*|tunl0$|vxlan.calico$|wireguard.cali$|wg-v6.cali$)",
		BPFConnectTimeLoadBalancing:    ptr("TCP"),
		BPFExternalServiceMode:        "Tunnel",
		BPFMapSizeConntrack:            ptr(512000),
		BPFMapSizeNATFrontend:          ptr(65536),
		BPFMapSizeNATBackend:           ptr(262144),
		DefaultEndpointToHostAction:    "Drop",
		IptablesFilterAllowAction:      "Accept",
		IptablesMangleAllowAction:      "Accept",
		LogSeverityScreen:              "Info",
		VXLANEnabled:                   ptr(true),
		VXLANVNI:                       ptr(4096),
		VXLANPort:                      ptr(4789),
		AllowVXLANPacketsFromWorkloads: ptr(false),
		AllowIPIPPacketsFromWorkloads:  ptr(false),
		TyphaAddr:                      "calico-typha:5473",
		TyphaReadTimeout:               ptr("30s"),
		TyphaWriteTimeout:              ptr("10s"),
	}
}

func makeSyncUpdates(n int) []serializedUpdate {
	updates := make([]serializedUpdate, n)
	for i := range n {
		updates[i] = serializedUpdate{
			Key:        "WorkloadEndpoint(node=node-1,orchestrator=k8s,workload=default/pod-" + string(rune('a'+i%26)) + ",name=eth0)",
			Value:      []byte(`{"labels":{"app":"web","version":"v2"},"ipNetworks":["10.244.1.` + string(rune('0'+i%10)) + `/32"],"profiles":["kns.default","ksa.default.default"]}`),
			Revision:   i + 1000,
			TTL:        int64(time.Hour),
			UpdateType: 1,
		}
	}
	return updates
}

func makeLabeledObject() labeledObject {
	return labeledObject{
		Name: "calico-node-abcde",
		Labels: map[string]string{
			"kubernetes.io/os":                "linux",
			"kubernetes.io/arch":              "amd64",
			"kubernetes.io/hostname":          "node-1.us-east-1.compute.internal",
			"node.kubernetes.io/instance-type": "m5.xlarge",
			"topology.kubernetes.io/zone":      "us-east-1a",
			"topology.kubernetes.io/region":    "us-east-1",
			"projectcalico.org/role":           "infrastructure",
			"env":                              "production",
			"team":                             "platform",
			"cluster":                          "prod-east-1",
		},
	}
}

// ---- Benchmarks ----

// BenchmarkPolicyMarshal - GlobalNetworkPolicy with 4 rules, selectors, CIDRs.
// Represents the policy hot path.
func BenchmarkPolicyMarshal(b *testing.B) {
	pol := makePolicy()
	b.Run("v1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := json.Marshal(pol)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := jsonv2.Marshal(pol)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPolicyUnmarshal(b *testing.B) {
	data, _ := json.Marshal(makePolicy())
	b.Run("v1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var pol policyResource
			if err := json.Unmarshal(data, &pol); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var pol policyResource
			if err := jsonv2.Unmarshal(data, &pol); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkFelixConfigMarshal - FelixConfigurationSpec with ~30 fields,
// heavy pointer usage. Represents config sync.
func BenchmarkFelixConfigMarshal(b *testing.B) {
	cfg := makeFelixConfig()
	b.Run("v1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := json.Marshal(cfg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := jsonv2.Marshal(cfg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkFelixConfigUnmarshal(b *testing.B) {
	data, _ := json.Marshal(makeFelixConfig())
	b.Run("v1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var cfg felixConfigSpec
			if err := json.Unmarshal(data, &cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var cfg felixConfigSpec
			if err := jsonv2.Unmarshal(data, &cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSyncBatchMarshal - Batch of 50 SerializedUpdates.
// Represents the Typha→Felix sync hot path.
func BenchmarkSyncBatchMarshal(b *testing.B) {
	updates := makeSyncUpdates(50)
	b.Run("v1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := json.Marshal(updates)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := jsonv2.Marshal(updates)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkSyncBatchUnmarshal(b *testing.B) {
	data, _ := json.Marshal(makeSyncUpdates(50))
	b.Run("v1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var updates []serializedUpdate
			if err := json.Unmarshal(data, &updates); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var updates []serializedUpdate
			if err := jsonv2.Unmarshal(data, &updates); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkLabelsMarshal - 10-label Kubernetes object.
// Labels are the most frequently serialized map type.
func BenchmarkLabelsMarshal(b *testing.B) {
	obj := makeLabeledObject()
	b.Run("v1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := json.Marshal(obj)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, err := jsonv2.Marshal(obj)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkLabelsUnmarshal(b *testing.B) {
	data, _ := json.Marshal(makeLabeledObject())
	b.Run("v1", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var obj labeledObject
			if err := json.Unmarshal(data, &obj); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var obj labeledObject
			if err := jsonv2.Unmarshal(data, &obj); err != nil {
				b.Fatal(err)
			}
		}
	})
}
