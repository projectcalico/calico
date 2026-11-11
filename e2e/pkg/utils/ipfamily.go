// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

type IPFamily int

const (
	IPv4 IPFamily = iota
	IPv6
)

var allIPFamilies = []IPFamily{IPv4, IPv6}

func (f IPFamily) String() string {
	if f == IPv6 {
		return "IPv6"
	}
	return "IPv4"
}

// HostBits is the prefix length of a single-address CIDR in this family.
func (f IPFamily) HostBits() int {
	if f == IPv6 {
		return 128
	}
	return 32
}

// HeaderBytes is the fixed IP header size, without options or extension headers.
func (f IPFamily) HeaderBytes() int {
	if f == IPv6 {
		return 40
	}
	return 20
}

// FamilyOf returns the family of a textual IP, and false if it doesn't parse.
func FamilyOf(ip string) (IPFamily, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return IPv4, false
	}
	if parsed.To4() != nil {
		return IPv4, true
	}
	return IPv6, true
}

// PodIPFor fails the spec rather than returning "", so a dual-stack node with a
// single-family pool shows up as a broken lane instead of a skipped family.
func PodIPFor(pod *corev1.Pod, f IPFamily) string {
	for _, ip := range pod.Status.PodIPs {
		if fam, ok := FamilyOf(ip.IP); ok && fam == f {
			return ip.IP
		}
	}
	framework.Failf("pod %s/%s has no %s address (PodIPs %v)", pod.Namespace, pod.Name, f, pod.Status.PodIPs)
	return ""
}
