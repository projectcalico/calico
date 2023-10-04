// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const numNamespaces = 100

func BenchmarkInitialSnapshot200Local250kTotal10000TagPols(b *testing.B) {
	benchInitialSnap(b, 250_000, 200, 10000, 0)
}

func BenchmarkInitialSnapshot200Local10kTotal1000NetsetPols(b *testing.B) {
	benchInitialSnap(b, 10000, 200, 0, 1000)
}

func BenchmarkInitialSnapshot200Local10kTotal10000NetsetPols(b *testing.B) {
	benchInitialSnap(b, 10000, 200, 0, 10000)
}

var (
	keepAlive any
	_         = keepAlive
)

func benchInitialSnap(b *testing.B, numEndpoints int, numLocalEndpoints int, numTagPols int, netSetsAndPols int) {
	RegisterTestingT(b)
	defer logrus.SetLevel(logrus.GetLevel())
	logrus.SetLevel(logrus.ErrorLevel)

	epUpdates := makeEndpointUpdates(numEndpoints, "remotehost")
	localUpdates := makeEndpointUpdates(numLocalEndpoints, "localhost")
	localDeletes := makeEndpointDeletes(numLocalEndpoints, "localhost")
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
		es.Callback = func(message interface{}) {
			numMessages++
		}
		cg := NewCalculationGraph(es, conf, func() {})
		keepAlive = cg // Keep CG alive after run so that memory profile shows its usage

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
		Expect(es.pendingEndpointTierUpdates).To(HaveLen(numLocalEndpoints))
		b.ReportMetric(float64(len(es.pendingAddedIPSets)), "IPSets")
		b.ReportMetric(float64(len(es.pendingPolicyUpdates)), "Policies")
		es.Flush()

		sendDeletions(cg, localDeletes)
		cg.Flush()
		es.Flush()

		b.ReportMetric(float64(time.Since(startTime).Seconds()), "s")
		b.ReportMetric(float64(numMessages), "Msgs")
	}
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
	for i := 0; i < num; i++ {
		// Make one netset and a matching policy.
		name := fmt.Sprintf("network-set-%d", i)
		netset := &model.NetworkSet{
			Nets: generateNetSetIPs(),
			Labels: map[string]string{
				"network-set-name": name,
			},
		}
		updates = append(updates, api.Update{
			KVPair: model.KVPair{
				Key:   model.NetworkSetKey{Name: name},
				Value: netset,
			},
		})

		pol := &model.Policy{}
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
	for i := 0; i < size; i++ {
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
	for i := 0; i < num; i++ {
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
	for i := 0; i < num; i++ {
		pol := &model.Policy{}
		pol.Selector = fmt.Sprintf("has(%s)", markerLabels[i%len(markerLabels)])
		for j := 0; j < rulesPerPol; j++ {
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
	for n := 0; n < num; n++ {
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
	for n := 0; n < num; n++ {
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

func generateLabels() map[string]string {
	labelSeed++
	labels := map[string]string{}
	for _, n := range []int{10, 11, 20, 30, 40} {
		labels[fmt.Sprintf("one-in-%d", n)] = fmt.Sprintf("value-%d", labelSeed%n)
	}
	labels[markerLabels[labelSeed%len(markerLabels)]] = "true"
	return labels
}
