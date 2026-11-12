// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package procsys

import (
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
)

// Writer has the signature of Write so that tests can substitute a fake.
type Writer func(path, value string) error

func Write(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

// ConfigureInterface applies the per-interface sysctls that Calico needs on
// workload-facing interfaces.
func ConfigureInterface(name string, ipVersion int, rpFilter string, write Writer) error {
	log.WithField("ifaceName", name).Info(
		"Applying /proc/sys configuration to interface.")

	if ipVersion == 4 {
		// Enable routing to localhost.  This is required to allow for NAT to the local
		// host.
		err := write(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", name), "1")
		if err != nil {
			return err
		}
		// Normally, the kernel has a delay before responding to proxy ARP but we know
		// that's not needed in a Calico network so we disable it.
		err = write(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", name), "0")
		if err != nil {
			log.Warnf("failed to set net.ipv4.neigh.%s.proxy_delay=0: %s", name, err)
		}
		// Enable proxy ARP, this makes the host respond to all ARP requests with its own
		// MAC.  This has a couple of advantages:
		//
		// - In OpenStack, we're forced to configure the guest's networking using DHCP.
		//   Since DHCP requires a subnet and gateway, representing the Calico network
		//   in the natural way would lose a lot of IP addresses.  For IPv4, we'd have to
		//   advertise a distinct /30 to each guest, which would use up 4 IPs per guest.
		//   Using proxy ARP, we can advertise the whole pool to each guest as its subnet
		//   but have the host respond to all ARP requests and route all the traffic whether
		//   it is on or off subnet.
		//
		// - For containers, we install explicit routes into the containers network
		//   namespace and we use a link-local address for the gateway.  ARP and proxy ARP
		//   are needed for that link-local address in the same way as for the gateway and
		//   subnet IPs in the OpenStack case.
		err = write(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", name), "1")
		if err != nil {
			return err
		}
		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		err = write(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", name), "1")
		if err != nil {
			return err
		}
		// Disable kernel rpf check for interfaces that have rpf filtering explicitly disabled
		// This is set only in IPv4 mode as there's no equivalent sysctl in IPv6
		err = write(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", name), rpFilter)
		if err != nil {
			return err
		}
	} else {
		// Note: deliberately no proxy_ndp counterpart to the proxy_arp above.
		// Despite the name, proxy_ndp is not the IPv6 equivalent: it does no
		// route-based proxying, and the kernel answers a Neighbor Solicitation
		// only for addresses with an explicit NUD_PROXY neighbour entry, which
		// Calico does not program.  IPv6 needs no proxying anyway, because Linux
		// auto-provisions a link-local address on this (host) side of every
		// workload interface, so the workload routes via a real address of ours
		// and we answer NDP for it as our own.  IPv4 has no such automatic
		// provisioning, hence the dummy 169.254.1.1 gateway and proxy ARP above.
		// See felix/design/neighbour-discovery.md.

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		err := write(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/forwarding", name), "1")
		if err != nil {
			return err
		}
	}

	return nil
}
