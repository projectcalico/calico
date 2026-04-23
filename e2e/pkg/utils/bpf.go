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

package utils

import (
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// DumpBPFNATServiceBackends returns the backend IPs for NAT map
// entries matching the specified service IP, port, and protocol.
//
// This uses the binary map format (via bpftool --json) and BPF pkg
// parsing logic, so it is immune to formatting changes in the
// human-readable `calico-node -bpf nat dump` output format.
func DumpBPFNATServiceBackends(cs kubernetes.Interface, nodeName string, serviceIP string, servicePort int, proto corev1.Protocol) (set.Set[string], error) {
	pod := GetCalicoNodePodOnNode(cs, nodeName)
	if pod == nil {
		return nil, fmt.Errorf("calico-node pod not found on node %s", nodeName)
	}

	protoNum := k8sProtoToIPProto(proto)
	if protoNum == 0 {
		return nil, fmt.Errorf("unsupported protocol %q", proto)
	}

	svcIP := net.ParseIP(serviceIP)
	if svcIP == nil {
		return nil, fmt.Errorf("invalid service IP %q", serviceIP)
	}

	if svcIP.To4() == nil {
		return findServiceBackends(pod, svcIP, uint16(servicePort), protoNum,
			nat.FrontendMapV6(), nat.MapMemV6Iter,
			nat.BackendMapV6(), nat.BackendMapMemV6Iter)
	}
	return findServiceBackends(pod, svcIP, uint16(servicePort), protoNum,
		nat.FrontendMap(), nat.MapMemIter,
		nat.BackendMap(), nat.BackendMapMemIter)
}

// frontendKey is the type constraint satisfied by nat.FrontendKey (v4) and
// nat.FrontendKeyV6. It adds comparable (needed for map keys) to the existing
// nat.FrontendKeyInterface.
type frontendKey interface {
	comparable
	nat.FrontendKeyInterface
}

// findServiceBackends dumps NAT maps using bpftool and
// searches for backends for the given service.
// IP-version-agnostic; uses the supplied Iter funcs to
// loop over whichever map it has dumped.
func findServiceBackends[
	FK frontendKey,
	BV nat.BackendValueInterface,
	FEMap ~map[FK]nat.FrontendValue,
	BEMap ~map[nat.BackendKey]BV,
](
	pod *corev1.Pod,
	svcIP net.IP,
	servicePort uint16,
	protoNum uint8,
	feMap maps.Map,
	loadFE func(FEMap) func(k, v []byte),
	beMap maps.Map,
	loadBE func(BEMap) func(k, v []byte),
) (set.Set[string], error) {
	nodeName := pod.Spec.NodeName

	// Dump and parse the frontend map, then find the matching service entry.
	feJSON, err := ExecInCalicoNode(pod, bpftoolDumpCmd(feMap))
	if err != nil {
		return nil, fmt.Errorf("failed to dump BPF NAT frontend map on node %s: %w", nodeName, err)
	}

	frontends := make(FEMap)
	if err := bpf.IterMapCmdOutput([]byte(feJSON), loadFE(frontends)); err != nil {
		return nil, fmt.Errorf("failed to parse BPF NAT frontend map on node %s: %w", nodeName, err)
	}

	var svcID, backendCount uint32
	found := false
	for feKey, feVal := range frontends {
		if feKey.Addr().Equal(svcIP) &&
			feKey.Port() == servicePort &&
			feKey.Proto() == protoNum &&
			feKey.SrcPrefixLen() == 0 {
			svcID = feVal.ID()
			backendCount = feVal.Count()
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no BPF NAT entry found for %s port %d proto %d on node %s",
			svcIP, servicePort, protoNum, nodeName)
	}

	// Dump and parse the backend map, then collect IPs for the matched service.
	beJSON, err := ExecInCalicoNode(pod, bpftoolDumpCmd(beMap))
	if err != nil {
		return nil, fmt.Errorf("failed to dump BPF NAT backend map on node %s: %w", nodeName, err)
	}

	backends := make(BEMap)
	if err := bpf.IterMapCmdOutput([]byte(beJSON), loadBE(backends)); err != nil {
		return nil, fmt.Errorf("failed to parse BPF NAT backend map on node %s: %w", nodeName, err)
	}

	ips := set.New[string]()
	for i := uint32(0); i < backendCount; i++ {
		beVal, ok := backends[nat.NewNATBackendKey(svcID, i)]
		if !ok {
			return nil, fmt.Errorf("missing backend ordinal %d for service ID %d on node %s", i, svcID, nodeName)
		}
		ips.Add(beVal.Addr().String())
	}

	return ips, nil
}

func bpftoolDumpCmd(m maps.Map) string {
	return fmt.Sprintf("bpftool --json map dump pinned %s", m.Path())
}

func k8sProtoToIPProto(proto corev1.Protocol) uint8 {
	switch proto {
	case corev1.ProtocolTCP:
		return 6
	case corev1.ProtocolUDP:
		return 17
	case corev1.ProtocolSCTP:
		return 132
	default:
		return 0
	}
}
