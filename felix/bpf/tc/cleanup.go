// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package tc

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// CleanUpProgramsAndPins makes a best effort to remove all our TC BPF programs.
func CleanUpProgramsAndPins() {
	log.Debug("Trying to clean up any left-over BPF state from a previous run.")
	bpftool := exec.Command("bpftool", "map", "list", "--json")
	mapsJSON, err := bpftool.Output()
	if err != nil {
		log.WithError(err).Info("Failed to list BPF maps, assuming there's nothing to clean up.")
		return
	}
	var maps []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	err = json.Unmarshal(mapsJSON, &maps)
	if err != nil {
		log.WithError(err).Info(
			"Failed to parse bpftool output.  Assuming BPF not supported/nothing to clean up.")
		return
	}
	calicoMapIDs := set.New[int]()
	for _, m := range maps {
		if strings.HasPrefix(m.Name, "cali_") || strings.HasPrefix(m.Name, "calico_") ||
			strings.HasPrefix(m.Name, "xdp_cali_") {
			log.WithField("name", m.Name).Debug("Found calico map")
			calicoMapIDs.Add(m.ID)
		}
	}

	calicoProgIDs := set.New[int]()
	if calicoMapIDs.Len() > 0 {
		// Have some calico maps, search for calico programs.
		bpftool := exec.Command("bpftool", "prog", "list", "--json")
		progsJSON, err := bpftool.Output()
		if err != nil {
			log.WithError(err).Info("Failed to list BPF programs, assuming there's nothing to clean up.")
			return
		}
		var progs []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Maps []int  `json:"map_ids"`
		}
		err = json.Unmarshal(progsJSON, &progs)
		if err != nil {
			log.WithError(err).Info("Failed to parse bpftool output.  Assuming nothing to clean up.")
			return
		}
		for _, p := range progs {
			if strings.HasPrefix(p.Name, "cali_") || strings.HasPrefix(p.Name, "calico_") {
				log.WithField("id", p.ID).Debug("Found calico program (by name)")
				calicoProgIDs.Add(p.ID)
				continue
			}
			for _, id := range p.Maps {
				if calicoMapIDs.Contains(id) {
					log.WithField("id", p.ID).Debug("Found calico program (by reference to calico map)")
					calicoProgIDs.Add(p.ID)
					break
				}
			}
		}
	}

	// Find all the interfaces with a clsact qdisc and examine the attached filters to see if any belong to
	// us.
	qdiscs, err := netlink.QdiscList(nil)
	if err != nil {
		log.WithError(err).Info("Failed to list qdiscs for cleanup")
	}
	for _, qdisc := range qdiscs {
		_, isClsact := qdisc.(*netlink.Clsact)
		if !isClsact {
			continue
		}
		link, err := netlink.LinkByIndex(qdisc.Attrs().LinkIndex)
		if err != nil {
			log.WithError(err).WithField("iface", link.Attrs().Name).Info(
				"Failed to remove BPF qdisc from interface, maybe interface is gone?")
		}
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, err := netlink.FilterList(link, parent)
			if err != nil {
				log.WithError(err).WithFields(log.Fields{"iface": link.Attrs().Name, "parent": parent}).Info(
					"Failed to list filters on interface for cleanup")
			}
			for _, filter := range filters {
				bpfFilter, ok := filter.(*netlink.BpfFilter)
				if !ok {
					continue
				}
				if calicoProgIDs.Contains(bpfFilter.Id) {
					log.Infof("Found calico program on interface %s", link.Attrs().Name)
					err := netlink.QdiscDel(qdisc)
					if err != nil {
						log.WithError(err).WithField("iface", link.Attrs().Name).Info(
							"Failed to remove BPF qdisc from interface, maybe interface is gone?")
					}
				}
			}
		}
	}
	// Remove all tcx pins
	os.RemoveAll(bpfdefs.TcxPinDir)
	bpf.CleanUpCalicoPins(bpfdefs.DefaultBPFfsPath)
}
