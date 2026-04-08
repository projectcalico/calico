// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package commands

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/linux/qos"
)

// QdiscStats holds the traffic statistics read from a TBF qdisc.
type QdiscStats struct {
	Bytes      uint64
	Packets    uint32
	Drops      uint32
	Overlimits uint32
	Backlog    uint32
	Rate       uint64 // configured rate (bits/sec)
}

// listCalicoInterfaces returns all cali* and tap* interfaces on the host.
func listCalicoInterfaces() ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list links: %w", err)
	}
	var ifaces []string
	for _, link := range links {
		name := link.Attrs().Name
		if strings.HasPrefix(name, "cali") || strings.HasPrefix(name, "tap") {
			ifaces = append(ifaces, name)
		}
	}
	return ifaces, nil
}

// listAllInterfaces returns all network interfaces on the host.
func listAllInterfaces() ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list links: %w", err)
	}
	var ifaces []string
	for _, link := range links {
		ifaces = append(ifaces, link.Attrs().Name)
	}
	return ifaces, nil
}

// readNICStats reads cumulative bytes from a host NIC.
func readNICStats(ifaceName string) (rxBytes, txBytes uint64, err error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get link %s: %w", ifaceName, err)
	}
	stats := link.Attrs().Statistics
	if stats == nil {
		return 0, 0, fmt.Errorf("no statistics for %s", ifaceName)
	}
	return stats.RxBytes, stats.TxBytes, nil
}

// readNICSpeed reads the link speed in bits/sec. Returns 0 if unavailable.
func readNICSpeed(ifaceName string) uint64 {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return 0
	}
	// link.Attrs().Speed is not available in all netlink versions.
	// Fall back to reading sysfs.
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/speed", ifaceName))
	if err != nil {
		log.WithError(err).WithField("iface", ifaceName).Debug("Failed to read NIC speed")
		_ = link // suppress unused
		return 0
	}
	var speedMbps uint64
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &speedMbps)
	return speedMbps * 1_000_000 // convert Mbps to bps
}

// readTBFStats reads the TBF qdisc statistics from a network interface.
func readTBFStats(linkName string) (*QdiscStats, error) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return nil, fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, fmt.Errorf("failed to list qdiscs on link %s: %w", linkName, err)
	}

	for _, qd := range qdiscs {
		tbf, ok := qd.(*netlink.Tbf)
		if !ok {
			continue
		}
		stats := &QdiscStats{
			Rate: tbf.Rate * 8, // netlink reports bytes/sec, convert to bits/sec
		}
		if s := qd.Attrs().Statistics; s != nil {
			if s.Basic != nil {
				stats.Bytes = s.Basic.Bytes
				stats.Packets = s.Basic.Packets
			}
			if s.Queue != nil {
				stats.Drops = s.Queue.Drops
				stats.Overlimits = s.Queue.Overlimits
				stats.Backlog = s.Queue.Backlog
			}
		}
		return stats, nil
	}

	return nil, nil
}

// ReadPodStats reads the ingress and egress qdisc stats for a pod's workload interface.
func ReadPodStats(ifaceName string) (*QdiscStats, *QdiscStats, error) {
	// Ingress: TBF on the workload interface (cali... or tap...).
	ingress, err := readTBFStats(ifaceName)
	if err != nil {
		log.WithError(err).WithField("iface", ifaceName).Debug("Failed to read ingress qdisc stats")
	}

	// Egress: TBF on the IFB device (bwcali...).
	ifbName := qos.GetIfbDeviceName(ifaceName)
	egress, err := readTBFStats(ifbName)
	if err != nil {
		log.WithError(err).WithField("iface", ifbName).Debug("Failed to read egress qdisc stats")
	}

	return ingress, egress, nil
}

// FormatBits formats a bits/sec value into a human-readable string.
func FormatBits(bitsPerSec uint64) string {
	switch {
	case bitsPerSec >= 1_000_000_000:
		return fmt.Sprintf("%.1f Gbps", float64(bitsPerSec)/1_000_000_000)
	case bitsPerSec >= 1_000_000:
		return fmt.Sprintf("%.1f Mbps", float64(bitsPerSec)/1_000_000)
	case bitsPerSec >= 1_000:
		return fmt.Sprintf("%.1f Kbps", float64(bitsPerSec)/1_000)
	default:
		return fmt.Sprintf("%d bps", bitsPerSec)
	}
}

// FormatBytes formats a byte count into a human-readable string.
func FormatBytes(bytes uint64) string {
	switch {
	case bytes >= 1_000_000_000:
		return fmt.Sprintf("%.1f GB", float64(bytes)/1_000_000_000)
	case bytes >= 1_000_000:
		return fmt.Sprintf("%.1f MB", float64(bytes)/1_000_000)
	case bytes >= 1_000:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1_000)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
