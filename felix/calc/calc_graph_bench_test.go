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
// Simulates a multi-tenant SaaS cluster: many identical namespaces each with
// a handful of pods (frontend*2, backend*2, database) and a namespaced Calico
// NetworkPolicy allowing frontend→backend, backend→database, and DNS egress.
// A "system" namespace has monitoring pods that can reach all customers.

func BenchmarkIsolatedCustomers1k(b *testing.B) {
	benchIsolatedCustomers(b, 1_000, 100)
}

func BenchmarkIsolatedCustomers10k(b *testing.B) {
	benchIsolatedCustomers(b, 10_000, 100)
}

func BenchmarkIsolatedCustomers100k(b *testing.B) {
	benchIsolatedCustomers(b, 100_000, 100)
}

const (
	podsPerCustomer     = 5 // 2 frontend + 2 backend + 1 database
	monitoringPods      = 10
	localMonitoringPods = 2
	kubeDNSCIDR         = "10.96.0.10/32"
	nsLabelKey          = conversion.NamespaceLabelPrefix + conversion.NameLabel
	nsProfilePrefix     = conversion.NamespaceProfileNamePrefix
	systemNamespace     = "system"
	systemNSProfileName = nsProfilePrefix + systemNamespace
)

func benchIsolatedCustomers(b *testing.B, numCustomers, numLocalEps int) {
	RegisterTestingT(b)
	defer logrus.SetLevel(logrus.GetLevel())
	logrus.SetLevel(logrus.ErrorLevel)

	nsUpdates := makeCustomerNamespaceUpdates(numCustomers)
	polUpdates := makeCustomerPolicies(numCustomers)
	remoteEpUpdates, localEpUpdates := makeAllCustomerEndpoints(numCustomers, numLocalEps)

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
// customer namespace and the system namespace.
func makeCustomerNamespaceUpdates(numCustomers int) []api.Update {
	total := numCustomers + 1 // +1 for system namespace
	updates := make([]api.Update, 0, 2*total)

	addNS := func(name string) {
		profName := nsProfilePrefix + name
		prof := &v3.Profile{
			Spec: v3.ProfileSpec{
				LabelsToApply: map[string]string{
					nsLabelKey: name,
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

	for n := 0; n < numCustomers; n++ {
		addNS(fmt.Sprintf("customer-%d", n))
	}
	addNS(systemNamespace)

	return updates
}

// makeCustomerPolicies creates one namespaced policy per deployment per
// customer namespace (frontend, backend, database = 3 per namespace) plus
// one global monitoring egress policy for the system namespace.
func makeCustomerPolicies(numCustomers int) []api.Update {
	tcp := numorstring.ProtocolFromString("TCP")
	udp := numorstring.ProtocolFromString("UDP")
	port8080 := numorstring.SinglePort(8080)
	port5432 := numorstring.SinglePort(5432)
	port53 := numorstring.SinglePort(53)
	port9090 := numorstring.SinglePort(9090)

	_, dnsNet, _ := calinet.ParseCIDROrIP(kubeDNSCIDR)

	dnsEgressRule := model.Rule{
		Action:   "Allow",
		Protocol: &udp,
		DstNets:  []*calinet.IPNet{dnsNet},
		DstPorts: []numorstring.Port{port53},
	}
	monitoringIngressRule := model.Rule{
		Action:      "Allow",
		Protocol:    &tcp,
		SrcSelector: fmt.Sprintf("%s == '%s' && role == 'monitoring'", nsLabelKey, systemNamespace),
		DstPorts:    []numorstring.Port{port9090},
	}

	polsPerCustomer := 3 // frontend, backend, database
	updates := make([]api.Update, 0, numCustomers*polsPerCustomer+1)

	for n := 0; n < numCustomers; n++ {
		ns := fmt.Sprintf("customer-%d", n)
		nsSelector := fmt.Sprintf("%s == '%s'", nsLabelKey, ns)

		// -- frontend policy --
		// Selector targets only frontend pods.
		// Ingress: monitoring → frontend (metrics scrape)
		// Egress: frontend → backend (TCP/8080), DNS
		frontendPol := &model.Policy{
			Namespace: ns,
			Tier:      "default",
			Selector:  nsSelector + " && role == 'frontend'",
			Types:     []string{"ingress", "egress"},
			InboundRules: []model.Rule{
				monitoringIngressRule,
			},
			OutboundRules: []model.Rule{
				{
					Action:      "Allow",
					Protocol:    &tcp,
					DstSelector: nsSelector + " && role == 'backend'",
					DstPorts:    []numorstring.Port{port8080},
				},
				dnsEgressRule,
			},
		}
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.PolicyKey{Name: fmt.Sprintf("customer-%d/frontend", n), Namespace: ns},
				Value: frontendPol,
			},
		})

		// -- backend policy --
		// Selector targets only backend pods.
		// Ingress: frontend → backend (TCP/8080), monitoring → backend
		// Egress: backend → database (TCP/5432), DNS
		backendPol := &model.Policy{
			Namespace: ns,
			Tier:      "default",
			Selector:  nsSelector + " && role == 'backend'",
			Types:     []string{"ingress", "egress"},
			InboundRules: []model.Rule{
				{
					Action:      "Allow",
					Protocol:    &tcp,
					SrcSelector: nsSelector + " && role == 'frontend'",
					DstPorts:    []numorstring.Port{port8080},
				},
				monitoringIngressRule,
			},
			OutboundRules: []model.Rule{
				{
					Action:      "Allow",
					Protocol:    &tcp,
					DstSelector: nsSelector + " && role == 'database'",
					DstPorts:    []numorstring.Port{port5432},
				},
				dnsEgressRule,
			},
		}
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.PolicyKey{Name: fmt.Sprintf("customer-%d/backend", n), Namespace: ns},
				Value: backendPol,
			},
		})

		// -- database policy --
		// Selector targets only database pods.
		// Ingress: backend → database (TCP/5432), monitoring → database
		// Egress: DNS only
		databasePol := &model.Policy{
			Namespace: ns,
			Tier:      "default",
			Selector:  nsSelector + " && role == 'database'",
			Types:     []string{"ingress", "egress"},
			InboundRules: []model.Rule{
				{
					Action:      "Allow",
					Protocol:    &tcp,
					SrcSelector: nsSelector + " && role == 'backend'",
					DstPorts:    []numorstring.Port{port5432},
				},
				monitoringIngressRule,
			},
			OutboundRules: []model.Rule{
				dnsEgressRule,
			},
		}
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.PolicyKey{Name: fmt.Sprintf("customer-%d/database", n), Namespace: ns},
				Value: databasePol,
			},
		})
	}

	// Global monitoring egress policy.
	monitoringPol := &model.Policy{
		Tier:     "default",
		Selector: fmt.Sprintf("%s == '%s' && role == 'monitoring'", nsLabelKey, systemNamespace),
		Types:    []string{"egress"},
		OutboundRules: []model.Rule{
			{
				Action:      "Allow",
				Protocol:    &tcp,
				DstSelector: "has(role)",
				DstPorts:    []numorstring.Port{port9090},
			},
			dnsEgressRule,
		},
	}
	updates = append(updates, api.Update{
		KVPair: model.KVPair{
			Key:   model.PolicyKey{Name: "system-monitoring-egress"},
			Value: monitoringPol,
		},
	})

	return updates
}

// k8sPodName generates a realistic K8s pod name following the
// <deployment>-<replicaset-hash>-<pod-hash> convention.
func k8sPodName(deployment string, nsIdx, replicaIdx int) string {
	// Deterministic but realistic-looking 9+5 char hex suffixes.
	rsHash := fmt.Sprintf("%09x", uint32(nsIdx*7+3))[:9]
	podHash := fmt.Sprintf("%05x", uint16(replicaIdx*13+nsIdx*17+5))[:5]
	return fmt.Sprintf("%s-%s-%s", deployment, rsHash, podHash)
}

type podTemplate struct {
	deployment string
	replica    int
	labels     map[string]string
}

var customerPodTemplates = []podTemplate{
	{"frontend", 0, map[string]string{"role": "frontend", "app": "web"}},
	{"frontend", 1, map[string]string{"role": "frontend", "app": "web"}},
	{"backend", 0, map[string]string{"role": "backend", "app": "api"}},
	{"backend", 1, map[string]string{"role": "backend", "app": "api"}},
	{"database", 0, map[string]string{"role": "database", "app": "db"}},
}

// makeAllCustomerEndpoints creates all endpoints across customer and system
// namespaces, assigning each pod to exactly one host. numLocalEps pods
// (including localMonitoringPods monitoring pods) are placed on "localhost",
// scattered across namespaces to simulate realistic K8s scheduling. The
// remainder go to "remotehost". Returns (remote, local) slices.
func makeAllCustomerEndpoints(numCustomers, numLocalEps int) (remote, local []api.Update) {
	totalCustomerEps := numCustomers * podsPerCustomer
	totalEps := totalCustomerEps + monitoringPods

	// Reserve some local slots for monitoring pods.
	numLocalCustomerEps := numLocalEps - localMonitoringPods
	if numLocalCustomerEps < 0 {
		numLocalCustomerEps = 0
	}
	if numLocalCustomerEps > totalCustomerEps {
		numLocalCustomerEps = totalCustomerEps
	}

	// Determine stride for scattering local pods across all customer pods.
	// Every stride-th customer pod lands on localhost.
	stride := 1
	if numLocalCustomerEps > 0 {
		stride = totalCustomerEps / numLocalCustomerEps
		if stride < 1 {
			stride = 1
		}
	}

	remote = make([]api.Update, 0, totalEps-numLocalEps)
	local = make([]api.Update, 0, numLocalEps)

	localCustomerCount := 0
	epIdx := 0
	for n := 0; n < numCustomers; n++ {
		ns := fmt.Sprintf("customer-%d", n)
		profID := nsProfilePrefix + ns
		for _, t := range customerPodTemplates {
			podName := k8sPodName(t.deployment, n, t.replica)
			if localCustomerCount < numLocalCustomerEps && epIdx%stride == 0 {
				local = append(local, makeCustomerWEP(
					"localhost", ns, podName, profID, t.labels,
				))
				localCustomerCount++
			} else {
				remote = append(remote, makeCustomerWEP(
					"remotehost", ns, podName, profID, t.labels,
				))
			}
			epIdx++
		}
	}

	// System namespace monitoring pods: first localMonitoringPods on
	// localhost, remainder on remotehost.
	for i := 0; i < monitoringPods; i++ {
		podName := k8sPodName("prometheus", 0, i)
		if i < localMonitoringPods {
			local = append(local, makeCustomerWEP(
				"localhost", systemNamespace, podName,
				systemNSProfileName,
				map[string]string{"role": "monitoring", "app": "prometheus"},
			))
		} else {
			remote = append(remote, makeCustomerWEP(
				"remotehost", systemNamespace, podName,
				systemNSProfileName,
				map[string]string{"role": "monitoring", "app": "prometheus"},
			))
		}
	}

	return remote, local
}

func makeCustomerWEP(host, ns, podName, profileID string, extraLabels map[string]string) api.Update {
	labels := make(map[string]string, len(extraLabels)+1)
	for k, v := range extraLabels {
		labels[k] = v
	}
	labels["customer"] = ns

	// Round-trip through JSON to make strings unique, matching real decoder behaviour.
	buf, err := json.Marshal(labels)
	if err != nil {
		panic(err)
	}
	labels = nil
	if err := json.Unmarshal(buf, &labels); err != nil {
		panic(err)
	}

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
