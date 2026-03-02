// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package calc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const numNamespaces = 100

func BenchmarkSnapshot200Local250kTotal10000TagPols(b *testing.B) {
	benchInitialSnap(b, 250_000, 200, 0, 10000, 0)
}

func BenchmarkSnapshot200Local10kTotal1000NetsetPols(b *testing.B) {
	benchInitialSnap(b, 10000, 200, 0, 0, 1000)
}

func BenchmarkSnapshot200Local10kTotal10000NetsetPols(b *testing.B) {
	benchInitialSnap(b, 10000, 200, 0, 0, 10000)
}

func BenchmarkSnapshotThenDeleteLocal200Local250kTotal10000TagPols(b *testing.B) {
	benchInitialSnap(b, 250_000, 200, 200, 10000, 0)
}

func BenchmarkSnapshotThenDeleteLocal200Local10kTotal1000NetsetPols(b *testing.B) {
	benchInitialSnap(b, 10000, 200, 200, 0, 1000)
}

func BenchmarkSnapshotThenDeleteLocal200Local10kTotal10000NetsetPols(b *testing.B) {
	benchInitialSnap(b, 10000, 200, 200, 0, 10000)
}

var (
	// Using a global instead of runtime.KeepAlive() so that the most-recent
	// CalcGraph stays alive after the benchmark completes, allowing for
	// capture of a memory profile.
	cg *CalcGraph
)

func benchInitialSnap(
	b *testing.B,
	numEndpoints int,
	numLocalEndpoints int,
	numLocalEndpointsToDelete int,
	numTagPols int,
	netSetsAndPols int,
) {
	RegisterTestingT(b)
	defer logrus.SetLevel(logrus.GetLevel())
	logrus.SetLevel(logrus.ErrorLevel)

	epUpdates := makeEndpointUpdates(numEndpoints, "remotehost")
	localUpdates := makeEndpointUpdates(numLocalEndpoints, "localhost")
	localDeletes := makeEndpointDeletes(numLocalEndpointsToDelete, "localhost")
	polUpdates := makeTagPolicies(numTagPols)
	profUpdates := makeNamespaceUpdates(numNamespaces)
	netSetUpdates := makeNetSetAndPolUpdates(netSetsAndPols)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		runtime.GC()
		logrus.SetLevel(logrus.ErrorLevel)

		conf := config.New()
		conf.FelixHostname = "localhost"
		es := NewEventSequencer(conf)
		numMessages := 0
		es.Callback = func(message any) {
			numMessages++
		}
		cg = NewCalculationGraph(es, nil, conf, func() {})

		logrus.SetLevel(logrus.WarnLevel)
		b.StartTimer()
		b.ReportAllocs()
		startTime := time.Now()
		sendPolicyUpdates(cg, polUpdates)
		sendProfileUpdates(cg, profUpdates)
		sendEndpointUpdates(cg, epUpdates)
		sendNetSetUpdates(cg, netSetUpdates)
		sendLocalUpdates(cg, localUpdates)
		cg.AllUpdDispatcher.OnDatamodelStatus(api.InSync)

		cg.Flush()
		Expect(es.pendingEndpointUpdates).To(HaveLen(numLocalEndpoints))
		b.ReportMetric(float64(len(es.pendingAddedIPSets)), "IPSets")
		b.ReportMetric(float64(len(es.pendingPolicyUpdates)), "Policies")
		es.Flush()

		sendDeletions(cg, localDeletes)
		cg.Flush()
		es.Flush()

		b.ReportMetric(float64(time.Since(startTime).Seconds()), "s")
		b.ReportMetric(float64(numMessages), "Msgs")
	}
	b.StopTimer()

	// Add the size of the heap to the benchmark output.  Trigger a GC and then
	// sleep to allow any runtime.Cleanup()s to finish.
	runtime.GC()
	time.Sleep(time.Second)
	// Read the stats.
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	b.ReportMetric(float64(m.HeapAlloc)/(1024*1024), "HeapAllocMB")
}

// These trivial functions are broken out so that, when CPU profiling, each
// operation can be seen separately in the profile.

func sendPolicyUpdates(cg *CalcGraph, polUpdates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(polUpdates)
}

func sendProfileUpdates(cg *CalcGraph, profUpdates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(profUpdates)
}

func sendEndpointUpdates(cg *CalcGraph, epUpdates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(epUpdates)
}

func sendNetSetUpdates(cg *CalcGraph, netSetUpdates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(netSetUpdates)
}

func sendLocalUpdates(cg *CalcGraph, localUpdates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(localUpdates)
}

func sendDeletions(cg *CalcGraph, localDeletes []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(localDeletes)
}

func makeNetSetAndPolUpdates(num int) []api.Update {
	updates := make([]api.Update, 0, num*2)
	for i := range num {
		// Make one netset and a matching policy.
		name := fmt.Sprintf("network-set-%d", i)
		netset := &model.NetworkSet{
			Nets: generateNetSetIPs(),
			Labels: uniquelabels.Make(map[string]string{
				"network-set-name": name,
			}),
		}
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.NetworkSetKey{Name: name},
				Value: netset,
			},
		})

		pol := &model.Policy{Tier: "default"}
		pol.Selector = "all()"
		pol.InboundRules = append(pol.InboundRules, model.Rule{
			Action:      "Allow",
			SrcSelector: fmt.Sprintf("network-set-name == '%s'", name),
		})
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.PolicyKey{Name: fmt.Sprintf("network-set-pol-%d", i)},
				Value: pol,
			},
		})
	}
	return updates
}

var nextNetSetIP uint32 = 0xa000001
var nextNetSetSizeIdx int
var netSetSizes = []int{
	1, 1, 1, 1, 2, 3, 4, 5,
	100,
	1000,
}

func generateNetSetIPs() (ips []calinet.IPNet) {
	size := netSetSizes[nextNetSetSizeIdx%len(netSetSizes)]
	nextNetSetSizeIdx++
	for range size {
		theIP := net.IPv4(0, 0, 0, 0)
		binary.BigEndian.PutUint32(theIP, nextNetSetIP)
		_, n, _ := calinet.ParseCIDROrIP(theIP.String())
		ips = append(ips, *n)
		nextNetSetIP++
	}
	return
}

func makeNamespaceUpdates(num int) []api.Update {
	updates := make([]api.Update, 0, 2*num)
	for i := range num {
		name := fmt.Sprintf("namespace-%d", i)
		prof := &v3.Profile{
			Spec: v3.ProfileSpec{
				LabelsToApply: map[string]string{
					conversion.NamespaceLabelPrefix + conversion.NameLabel: name,
				},
			},
		}

		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Kind: v3.KindProfile, Name: conversion.NamespaceProfileNamePrefix + name},
				Value: prof,
			},
		})
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key: model.ProfileRulesKey{
					ProfileKey: model.ProfileKey{Name: conversion.NamespaceProfileNamePrefix + name},
				},
				Value: &model.ProfileRules{
					InboundRules:  nil,
					OutboundRules: nil,
				},
			},
		})
	}
	return updates
}

var nextTagPolID int

func makeTagPolicies(num int) []api.Update {
	const rulesPerPol = 5
	updates := make([]api.Update, 0, num)
	for i := range num {
		pol := &model.Policy{Tier: "default"}
		pol.Selector = fmt.Sprintf("has(%s)", markerLabels[i%len(markerLabels)])
		for j := range rulesPerPol {
			pol.InboundRules = append(pol.InboundRules, model.Rule{
				Action:      "Allow",
				SrcSelector: fmt.Sprintf("has(%s)", markerLabels[(nextTagPolID+j)%len(markerLabels)]),
			})
		}

		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.PolicyKey{Name: fmt.Sprintf("tag-pol-%d", nextTagPolID)},
				Value: pol,
			},
		})

		nextTagPolID++
	}
	return updates
}

func makeEndpointUpdates(num int, host string) []api.Update {
	updates := make([]api.Update, num)
	for n := range num {
		key := model.WorkloadEndpointKey{
			Hostname:       host,
			OrchestratorID: "k8s",
			WorkloadID:     fmt.Sprintf("wep-%d", n),
			EndpointID:     "eth0",
		}
		ipNet := getNextIP()
		updates[n] = api.Update{
			KVPair: model.KVPair{
				Key: key,
				Value: &model.WorkloadEndpoint{
					Labels:     generateLabels(),
					IPv4Nets:   []calinet.IPNet{ipNet},
					ProfileIDs: []string{fmt.Sprintf(conversion.NamespaceProfileNamePrefix+"namespace-%d", n%numNamespaces)},
				},
			},
		}
	}
	return updates
}
func makeEndpointDeletes(num int, host string) []api.Update {
	updates := make([]api.Update, num)
	for n := range num {
		key := model.WorkloadEndpointKey{
			Hostname:       host,
			OrchestratorID: "k8s",
			WorkloadID:     fmt.Sprintf("wep-%d", n),
			EndpointID:     "eth0",
		}
		updates[n] = api.Update{
			KVPair: model.KVPair{
				Key:   key,
				Value: nil,
			},
		}
	}
	return updates
}

var nextIP uint32 = 0xa000001

func getNextIP() calinet.IPNet {
	theIP := net.IPv4(0, 0, 0, 0)
	binary.BigEndian.PutUint32(theIP, nextIP)
	nextIP++
	return calinet.IPNet{IPNet: net.IPNet{
		IP:   theIP,
		Mask: net.CIDRMask(32, 32),
	}}
}

var markerLabels = []string{
	"FOO_BAR",
	"FOO_BAR",
	"BIFF_BOP",
	"calico/FizzBuzz",
	"calico/BoffBip",
	"calico/Bazzle",
	"calico/Razzle",
	"calico/DoopDeeDoo",
	"calico/SOME_LABEL",
	"calico/BORED_NOW",
	"MyMarkerLabel",
	"xFOO_BAR",
	"xBIFF_BOP",
	"xcalico/FizzBuzz",
	"xcalico/BoffBip",
	"xcalico/Bazzle",
	"xcalico/Razzle",
	"xcalico/DoopDeeDoo",
	"xcalico/SOME_LABEL",
	"xcalico/BORED_NOW",
	"yxMyMarkerLabel",
	"yxFOO_BAR",
	"yxBIFF_BOP",
	"yxcalico/FizzBuzz",
	"yxcalico/BoffBip",
	"yxcalico/Bazzle",
	"yxcalico/Razzle",
	"yxcalico/DoopDeeDoo",
	"yxcalico/SOME_LABEL",
	"yxcalico/BORED_NOW",
	"yxMyMarkerLabel",
}

var labelSeed int

func generateLabels() uniquelabels.Map {
	labelSeed++
	labels := map[string]string{}
	for _, n := range []int{10, 11, 20, 30, 40} {
		labels[fmt.Sprintf("one-in-%d", n)] = fmt.Sprintf("value-%d", labelSeed%n)
	}
	labels[markerLabels[(labelSeed)%len(markerLabels)]] = "true"

	// Round trip through JSON; this makes every string unique, simulating
	// what happens when we decode strings for real in felix.
	buf, err := json.Marshal(labels)
	if err != nil {
		panic(err)
	}
	labels = nil
	err = json.Unmarshal(buf, &labels)
	if err != nil {
		panic(err)
	}

	return uniquelabels.Make(labels)
}

// --- Isolated customer environments benchmark ---
//
// Simulates a multi-tenant SaaS cluster with many identical namespaces, each
// containing uniform pods. Pod and namespace labels are modelled on a real
// SaaS deployment with realistic cardinalities.
//
// Pod labels (15):
//   - 5 unique-per-pod (string lengths 20, 20, 10, 20, 8)
//   - 4 binary (values "0" or "1")
//   - 4 small-set (environment, tier, region, team)
//   - 1 marker (identical on every pod)
//   - 1 high-cardinality (~5000 distinct values, 10 chars)
//
// Namespace labels (3, applied via Profile):
//   - kubernetes.io/metadata.name (= namespace name)
//   - namespace-id: unique 20-char identifier
//   - production: boolean "true"/"false"

func BenchmarkIsolatedCustomers1k(b *testing.B) {
	benchIsolatedCustomers(b, 1_000, 1, 100)
}

func BenchmarkIsolatedCustomers10k(b *testing.B) {
	benchIsolatedCustomers(b, 10_000, 1, 100)
}

func BenchmarkIsolatedCustomers100k(b *testing.B) {
	benchIsolatedCustomers(b, 100_000, 1, 100)
}

const (
	nsLabelKey      = conversion.NamespaceLabelPrefix + conversion.NameLabel
	nsProfilePrefix = conversion.NamespaceProfileNamePrefix
	kubeDNSCIDR     = "10.96.0.10/32"
)

func benchIsolatedCustomers(b *testing.B, numCustomers, podsPerNamespace, numLocalEps int) {
	RegisterTestingT(b)
	defer logrus.SetLevel(logrus.GetLevel())
	logrus.SetLevel(logrus.ErrorLevel)

	nsUpdates := makeCustomerNamespaceUpdates(numCustomers)
	polUpdates := makeCustomerPolicies(numCustomers)
	remoteEpUpdates, localEpUpdates := makeAllCustomerEndpoints(numCustomers, podsPerNamespace, numLocalEps)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		runtime.GC()
		logrus.SetLevel(logrus.ErrorLevel)

		conf := config.New()
		conf.FelixHostname = "localhost"
		es := NewEventSequencer(conf)
		numMessages := 0
		es.Callback = func(message interface{}) {
			numMessages++
		}
		cg = NewCalculationGraph(es, nil, conf, func() {})

		logrus.SetLevel(logrus.WarnLevel)
		b.StartTimer()
		b.ReportAllocs()
		startTime := time.Now()

		sendCustomerPolicies(cg, polUpdates)
		sendCustomerProfiles(cg, nsUpdates)
		sendCustomerRemoteEndpoints(cg, remoteEpUpdates)
		sendCustomerLocalEndpoints(cg, localEpUpdates)
		cg.AllUpdDispatcher.OnDatamodelStatus(api.InSync)

		cg.Flush()

		Expect(es.pendingEndpointUpdates).To(HaveLen(len(localEpUpdates)))

		b.ReportMetric(float64(len(localEpUpdates)), "LocalEps")
		b.ReportMetric(float64(len(es.pendingAddedIPSets)), "IPSets")
		b.ReportMetric(float64(len(es.pendingPolicyUpdates)), "Policies")
		es.Flush()

		b.ReportMetric(float64(time.Since(startTime).Seconds()), "s")
		b.ReportMetric(float64(numMessages), "Msgs")
	}
	b.StopTimer()

	runtime.GC()
	time.Sleep(time.Second)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	b.ReportMetric(float64(m.HeapAlloc)/(1024*1024), "HeapAllocMB")
}

// Broken out for CPU profiling visibility.

func sendCustomerPolicies(cg *CalcGraph, updates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(updates)
}

func sendCustomerProfiles(cg *CalcGraph, updates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(updates)
}

func sendCustomerRemoteEndpoints(cg *CalcGraph, updates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(updates)
}

func sendCustomerLocalEndpoints(cg *CalcGraph, updates []api.Update) {
	cg.AllUpdDispatcher.OnUpdates(updates)
}

// makeCustomerNamespaceUpdates creates Profile + ProfileRules for each
// customer namespace. Each namespace gets three labels:
//   - kubernetes.io/metadata.name (standard)
//   - namespace-id: unique 20-char identifier
//   - production: boolean "true"/"false"
func makeCustomerNamespaceUpdates(numCustomers int) []api.Update {
	updates := make([]api.Update, 0, 2*numCustomers)

	for n := 0; n < numCustomers; n++ {
		name := fmt.Sprintf("customer-%d", n)
		profName := nsProfilePrefix + name
		prof := &v3.Profile{
			Spec: v3.ProfileSpec{
				LabelsToApply: map[string]string{
					nsLabelKey:     name,
					"namespace-id": deterministicString(n, 20),
					"production":   fmt.Sprintf("%v", n%2 == 0),
				},
			},
		}
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Kind: v3.KindProfile, Name: profName},
				Value: prof,
			},
		})
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key: model.ProfileRulesKey{
					ProfileKey: model.ProfileKey{Name: profName},
				},
				Value: &model.ProfileRules{},
			},
		})
	}

	return updates
}

// makeCustomerPolicies creates one namespaced isolation policy per customer
// namespace: allows intra-namespace traffic and DNS egress.
func makeCustomerPolicies(numCustomers int) []api.Update {
	udp := numorstring.ProtocolFromString("UDP")
	port53 := numorstring.SinglePort(53)
	_, dnsNet, _ := calinet.ParseCIDROrIP(kubeDNSCIDR)

	updates := make([]api.Update, 0, numCustomers)

	for n := 0; n < numCustomers; n++ {
		ns := fmt.Sprintf("customer-%d", n)
		nsSelector := fmt.Sprintf("%s == '%s'", nsLabelKey, ns)

		pol := &model.Policy{
			Namespace: ns,
			Tier:      "default",
			Selector:  nsSelector,
			Types:     []string{"ingress", "egress"},
			InboundRules: []model.Rule{
				{
					Action:      "Allow",
					SrcSelector: nsSelector,
				},
			},
			OutboundRules: []model.Rule{
				{
					Action:      "Allow",
					DstSelector: nsSelector,
				},
				{
					Action:   "Allow",
					Protocol: &udp,
					DstNets:  []*calinet.IPNet{dnsNet},
					DstPorts: []numorstring.Port{port53},
				},
			},
		}
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.PolicyKey{Name: fmt.Sprintf("customer-%d/isolation", n), Namespace: ns},
				Value: pol,
			},
		})
	}

	return updates
}

// Small-set label values for pods.
var (
	saasEnvironments = []string{"dev", "staging", "prod"}
	saasPodTiers     = []string{"frontend", "backend", "middleware", "data"}
	saasRegions      = []string{"us-east", "us-west", "eu-west", "ap-south"}
	saasTeams        = []string{"platform", "payments", "identity", "growth", "infra"}
)

// makeAllCustomerEndpoints creates uniform pods across customer namespaces.
// numLocalEps pods are placed on "localhost" scattered via stride; the rest
// go to "remotehost". Returns (remote, local) slices.
func makeAllCustomerEndpoints(numCustomers, podsPerNamespace, numLocalEps int) (remote, local []api.Update) {
	totalEps := numCustomers * podsPerNamespace
	if numLocalEps > totalEps {
		numLocalEps = totalEps
	}

	stride := 1
	if numLocalEps > 0 {
		stride = totalEps / numLocalEps
		if stride < 1 {
			stride = 1
		}
	}

	remote = make([]api.Update, 0, totalEps-numLocalEps)
	local = make([]api.Update, 0, numLocalEps)

	localCount := 0
	epIdx := 0
	for n := 0; n < numCustomers; n++ {
		ns := fmt.Sprintf("customer-%d", n)
		profID := nsProfilePrefix + ns
		for p := 0; p < podsPerNamespace; p++ {
			podName := fmt.Sprintf("app-%09x-%05x", uint32(n*7+3), uint16(p*13+n*17+5))
			labels := makeCustomerPodLabels(epIdx)
			if localCount < numLocalEps && epIdx%stride == 0 {
				local = append(local, makeCustomerWEP("localhost", ns, podName, profID, labels))
				localCount++
			} else {
				remote = append(remote, makeCustomerWEP("remotehost", ns, podName, profID, labels))
			}
			epIdx++
		}
	}

	return remote, local
}

// makeCustomerPodLabels generates the 15 realistic labels for a pod at the
// given global index.
func makeCustomerPodLabels(podIdx int) map[string]string {
	labels := map[string]string{
		// 5 unique-per-pod labels with specified string lengths.
		"pod-id":      deterministicString(podIdx*5, 20),
		"instance-id": deterministicString(podIdx*5+1, 20),
		"short-id":    deterministicString(podIdx*5+2, 10),
		"config-hash": deterministicString(podIdx*5+3, 20),
		"version-tag": deterministicString(podIdx*5+4, 8),

		// 4 binary labels.
		"enabled": fmt.Sprintf("%d", podIdx%2),
		"debug":   fmt.Sprintf("%d", (podIdx/2)%2),
		"canary":  fmt.Sprintf("%d", (podIdx/4)%2),
		"managed": fmt.Sprintf("%d", (podIdx/8)%2),

		// 4 small-set labels.
		"environment": saasEnvironments[podIdx%len(saasEnvironments)],
		"tier":        saasPodTiers[podIdx%len(saasPodTiers)],
		"region":      saasRegions[podIdx%len(saasRegions)],
		"team":        saasTeams[podIdx%len(saasTeams)],

		// 1 marker label (same on every pod).
		"managed-by": "saas-controller",

		// 1 high-cardinality label (~5000 distinct values, 10 chars).
		"tenant-id": deterministicString(podIdx%5000, 10),
	}

	// Round-trip through JSON to make strings unique, matching real
	// decoder behaviour.
	buf, err := json.Marshal(labels)
	if err != nil {
		panic(err)
	}
	labels = nil
	if err := json.Unmarshal(buf, &labels); err != nil {
		panic(err)
	}

	return labels
}

// deterministicString returns a deterministic hex-like string of the given
// length, seeded by n.
func deterministicString(n, length int) string {
	const chars = "abcdef0123456789"
	b := make([]byte, length)
	v := uint64(n)*2654435761 + 1
	for i := range b {
		b[i] = chars[v%uint64(len(chars))]
		v = v*6364136223846793005 + 1442695040888963407
	}
	return string(b)
}

func makeCustomerWEP(host, ns, podName, profileID string, labels map[string]string) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key: model.WorkloadEndpointKey{
				Hostname:       host,
				OrchestratorID: "k8s",
				WorkloadID:     fmt.Sprintf("%s/%s", ns, podName),
				EndpointID:     "eth0",
			},
			Value: &model.WorkloadEndpoint{
				Labels:     uniquelabels.Make(labels),
				IPv4Nets:   []calinet.IPNet{getNextIP()},
				ProfileIDs: []string{profileID},
			},
		},
	}
}
