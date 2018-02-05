// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package policystore

import (
	"fmt"
	"strings"

	syncapi "github.com/projectcalico/app-policy/proto"

	envoyapi "github.com/envoyproxy/data-plane-api/api"
	log "github.com/sirupsen/logrus"
)

// IPSet is a data structure that contains IP addresses, or IP address/port pairs. It allows fast membership tests
// of Address objects from the authorization API.
type IPSet interface {
	// Idempotent add IP address to set.
	// ip depends on the IPSet type:
	// IP          - Each member is an IP address in dotted-decimal or IPv6 format.
	// IP_AND_PORT - Each member is "<IP>,(tcp|udp):<port-number>"
	AddString(ip string)

	// Idempotent remove IP address from set.
	// ip depends on the IPSet type:
	// IP          - Each member is an IP address in dotted-decimal or IPv6 format.
	// IP_AND_PORT - Each member is "<IP>,(tcp|udp):<port-number>"
	RemoveString(ip string)

	// Test if the address is contained in the set.
	ContainsAddress(addr *envoyapi.Address) bool
}

// We'll use golang's map type under the covers here because it is simple to implement.
// Later, we may wish to experiment with more memory optimized data structures, like radix trees.

type ipMapSet map[string]bool
type ipPortMapSet map[string]bool

// NewIPSet creates an IPSet of the appropriate type given by t.
func NewIPSet(t syncapi.IPSetUpdate_IPSetType) IPSet {
	switch t {
	case syncapi.IPSetUpdate_IP:
		return ipMapSet{}
	case syncapi.IPSetUpdate_IP_AND_PORT:
		return ipPortMapSet{}
	}
	panic("Unrecognized IPSet type")
}

func (m ipMapSet) AddString(ip string) {
	m[ip] = true
}

func (m ipMapSet) RemoveString(ip string) {
	delete(m, ip)
}

func (m ipMapSet) ContainsAddress(addr *envoyapi.Address) bool {
	sck := addr.GetSocketAddress()
	key := sck.GetAddress()
	log.WithFields(log.Fields{
		"proto": addr.String(),
		"key":   key,
	}).Debug("Finding address in ipMapSet", addr)
	return m[key]
}

func (m ipPortMapSet) AddString(ip string) {
	m[ip] = true
}

func (m ipPortMapSet) RemoveString(ip string) {
	delete(m, ip)
}

func (m ipPortMapSet) ContainsAddress(addr *envoyapi.Address) bool {
	sck := addr.GetSocketAddress()
	p := strings.ToLower(sck.GetProtocol().String())
	key := fmt.Sprintf("%v,%v:%d", sck.GetAddress(), p, sck.GetPortValue())
	log.WithFields(log.Fields{
		"proto": addr.String(),
		"key":   key,
	}).Debug("Finding address in ipPortMapSet", addr)
	return m[key]
}
