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
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/bpf"
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
		if strings.HasPrefix(m.Name, "cali_") || strings.HasPrefix(m.Name, "calico_") {
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
	calicoIfaces := set.New[string]()
	for _, iface := range ifacesWithClsact() {
		for _, dir := range []string{"ingress", "egress"} {
			tc := exec.Command("tc", "filter", "show", dir, "dev", iface)
			out, err := tc.Output()
			if err != nil {
				log.WithError(err).Debugf("Cleanup failed for interface %s; ignoring", iface)
			}
			for _, id := range findBPFProgIDs(out) {
				if calicoProgIDs.Contains(id) {
					log.Infof("Found calico program on interface %s", iface)
					calicoIfaces.Add(iface)
				}
			}
		}
	}

	calicoIfaces.Iter(func(iface string) error {
		cmd := exec.Command("tc", "qdisc", "del", "dev", iface, "clsact")
		err = cmd.Run()
		if err != nil {
			log.WithError(err).WithField("iface", iface).Info(
				"Failed to remove BPF program from interface, maybe interface has gone?")
		}
		return nil
	})

	bpf.CleanUpCalicoPins("/sys/fs/bpf/tc")
}

var tcFiltRegex = regexp.MustCompile(`filter .*? bpf .*? id (\d+)`)
var tcQdiscRegex = regexp.MustCompile(`qdisc clsact .*? dev ([^ ]+)`)

func ifacesWithClsact() []string {
	tc := exec.Command("tc", "qdisc", "list")
	out, err := tc.Output()
	if err != nil {
		log.WithError(err).Warn("Failed to run tc.")
		return nil
	}
	// Example line:
	// qdisc clsact ffff: dev cali866cd63afec parent ffff:fff1
	result := findClsactQdiscs(out)
	return result
}

func findClsactQdiscs(tcOutput []byte) []string {
	matches := tcQdiscRegex.FindAllSubmatch(tcOutput, -1)
	var result []string
	for _, m := range matches {
		result = append(result, string(m[1]))
	}
	return result
}

func findBPFProgIDs(tcOutput []byte) []int {
	matches := tcFiltRegex.FindAllSubmatch(tcOutput, -1)
	var result []int
	for _, m := range matches {
		id, err := strconv.Atoi(string(m[1]))
		if err != nil {
			log.WithError(err).Panic("Bug: failed to parse ID from regex.")
		}
		result = append(result, id)
	}
	return result
}
