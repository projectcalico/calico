// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2021  All rights reserved.

package failsafes

import (
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/logutils"
)

type Manager struct {
	// failsafesMap is the BPF map containing host enpodint failsafe ports.
	failsafesMap bpf.Map
	// failsafesInSync is set to true if the failsafe map is in sync.
	failsafesInSync bool
	// failsafesIn the inbound failsafe ports, from configuration.
	failsafesIn []config.ProtoPort
	// failsafesOut the outbound failsafe ports, from configuration.
	failsafesOut []config.ProtoPort

	opReporter logutils.OpRecorder
}

func (m *Manager) OnUpdate(_ interface{}) {
}

func NewManager(
	failsafesMap bpf.Map,
	failsafesIn, failsafesOut []config.ProtoPort,
	opReporter logutils.OpRecorder,
) *Manager {
	return &Manager{
		failsafesMap: failsafesMap,
		failsafesIn:  failsafesIn,
		failsafesOut: failsafesOut,
		opReporter:   opReporter,
	}
}

func (m *Manager) CompleteDeferredWork() error {
	if !m.failsafesInSync {
		return m.ResyncFailsafes()
	}
	return nil
}

func (m *Manager) ResyncFailsafes() error {
	m.opReporter.RecordOperation("resync-failsafes")

	syncFailed := false
	unknownKeys := set.New()
	err := m.failsafesMap.Iter(func(rawKey, _ []byte) bpf.IteratorAction {
		key := KeyFromSlice(rawKey)
		unknownKeys.Add(key)
		return bpf.IterNone
	})
	if err != nil {
		log.WithError(err).Panic("Failed to iterate failsafe ports map.")
	}

	addPort := func(p config.ProtoPort, outbound bool) {
		var ipProto uint8
		switch strings.ToLower(p.Protocol) {
		case "tcp":
			ipProto = 6
		case "udp":
			ipProto = 17
		default:
			log.WithField("proto", p.Protocol).Warn("Ignoring failsafe port; protocol not supported in BPF mode.")
			return
		}

		// Parse the CIDR and split out the IP and mask
		cidr := p.Net
		if p.Net == "" {
			cidr = "0.0.0.0/0"
		}
		ip, ipnet, err := cnet.ParseCIDROrIP(cidr)
		if err != nil {
			log.WithError(err).Error("Failed to parse CIDR for failsafe port")
			syncFailed = true
			return
		}

		ipv4 := ip.To4()
		if ipv4 == nil || len(ipv4) != 4 {
			// If ipv4 is nil, then the IP is not an IPv4 address. Only IPv4 addresses are supported in failsafes.
			log.Errorf("Invalid IPv4 address configured in the failsafe ports: %s", cidr)
			syncFailed = true
			return
		}

		mask, bits := ipnet.Mask.Size()
		if bits != 32 {
			log.Errorf("CIDR mask size not valid for IPv4 addresses: %d", bits)
			syncFailed = true
			return
		}

		// Mask the IP
		maskedIP := ipv4.Mask(ipnet.Mask)

		k := MakeKey(ipProto, p.Port, outbound, maskedIP.String(), mask)
		unknownKeys.Discard(k)
		err = m.failsafesMap.Update(k.ToSlice(), Value())
		if err != nil {
			log.WithError(err).WithField("key", k).Error("Failed to update failsafe port.")
			syncFailed = true
		} else {
			log.WithField("key", k).Debug("Installed failsafe port.")
		}
	}

	for _, p := range m.failsafesIn {
		addPort(p, false)
	}
	for _, p := range m.failsafesOut {
		addPort(p, true)
	}

	unknownKeys.Iter(func(item interface{}) error {
		k := item.(Key)
		err := m.failsafesMap.Delete(k.ToSlice())
		if err != nil {
			log.WithError(err).WithField("key", k).Warn("Failed to remove failsafe port from map.")
			syncFailed = true
		} else {
			log.WithField("key", k).Debug("Deleted failsafe port.")
		}
		return nil
	})

	m.failsafesInSync = !syncFailed
	if syncFailed {
		return errors.New("failed to sync failsafe ports")
	}
	return nil
}
