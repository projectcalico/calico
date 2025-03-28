// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	net2 "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	UnknownEndpoint  = "<unknown>"
	FieldNotIncluded = "-"
)

func IpStrTo16Byte(ipStr string) [16]byte {
	addr := net.ParseIP(ipStr)
	return IpTo16Byte(addr)
}

func IpTo16Byte(addr net.IP) [16]byte {
	var addrB [16]byte
	copy(addrB[:], addr.To16()[:16])
	return addrB
}

// endpointName is a convenience function to return a printable name for an endpoint.
func EndpointName(key model.Key) (name string) {
	switch k := key.(type) {
	case model.WorkloadEndpointKey:
		name = workloadEndpointName(k)
	case model.HostEndpointKey:
		name = hostEndpointName(k)
	}
	return
}

func workloadEndpointName(wep model.WorkloadEndpointKey) string {
	return "WEP(" + wep.Hostname + "/" + wep.OrchestratorID + "/" + wep.WorkloadID + "/" + wep.EndpointID + ")"
}

func hostEndpointName(hep model.HostEndpointKey) string {
	return "HEP(" + hep.Hostname + "/" + hep.EndpointID + ")"
}

func MustParseIP(s string) net2.IP {
	ip := net.ParseIP(s)
	return net2.IP{IP: ip}
}

func MustParseMac(m string) *net2.MAC {
	hwAddr, err := net.ParseMAC(m)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse MAC: %v; %v", m, err))
	}
	return &net2.MAC{HardwareAddr: hwAddr}
}

func MustParseNet(n string) net2.IPNet {
	_, cidr, err := net2.ParseCIDR(n)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse CIDR %v; %v", n, err))
	}
	return *cidr
}

func IntersectLabels(in, out map[string]string) map[string]string {
	common := map[string]string{}
	for k := range out {
		// Skip Calico labels from the logs
		if strings.HasPrefix(k, "projectcalico.org/") {
			continue
		}
		if v, ok := in[k]; ok && v == out[k] {
			common[k] = v
		}
	}

	return common
}

// There is support for both global and namespaced networkset. In case of
// namespaced networkset, aggregatedName is namespace/name format. Extract
// namespace and name from it.
func ExtractNamespaceFromNetworkSet(aggregatedName string) (string, string) {
	res := strings.Split(aggregatedName, "/")
	if (len(res)) > 1 {
		return res[0], res[1]
	}
	return FieldNotIncluded, aggregatedName
}

func FlattenLabels(labels map[string]string) []string {
	respSlice := []string{}
	for k, v := range labels {
		l := fmt.Sprintf("%v=%v", k, v)
		respSlice = append(respSlice, l)
	}
	return respSlice
}

func UnflattenLabels(labelSlice []string) map[string]string {
	resp := map[string]string{}
	for _, label := range labelSlice {
		labelKV := strings.Split(label, "=")
		if len(labelKV) != 2 {
			continue
		}
		resp[labelKV[0]] = labelKV[1]
	}
	return resp
}

var protoNames = map[int]string{
	1:   "icmp",
	6:   "tcp",
	17:  "udp",
	4:   "ipip",
	50:  "esp",
	58:  "icmp6",
	132: "sctp",
}

func ProtoToString(p int) string {
	s, ok := protoNames[p]
	if ok {
		return s
	}
	return strconv.Itoa(p)
}

func StringToProto(s string) int {
	for i, st := range protoNames {
		if s == st {
			return i
		}
	}
	p, _ := strconv.Atoi(s)
	return p
}
