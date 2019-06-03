// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package fv

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
)

type mapEntry struct {
	Key []string `json:"key"`
}

// Meh.
func strSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func waitForCgroupSubdir(felix *infrastructure.Felix, cgroupv2subdir string) error {
	maxTries := 10
	cgroupDir := filepath.Join("/run/calico/cgroup", cgroupv2subdir)
	for i := 0; i < maxTries; i++ {
		err := utils.Command("docker", "exec", felix.Container.Name,
			"sh", "-c",
			fmt.Sprintf("if [ -d '%s' ]; then exit 0; fi; exit 1;", cgroupDir)).Run()
		if err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%s did not appear in felix container", cgroupDir)
}

func testIPToHex(ip string) []string {
	cidr := fmt.Sprintf("%s/32", ip)
	hexen, err := bpf.CidrToHex(cidr)
	Expect(err).NotTo(HaveOccurred())
	for idx := range hexen {
		hexen[idx] = "0x" + hexen[idx]
	}
	return hexen
}

var _ = infrastructure.DatastoreDescribe("with initialized Felix", []apiconfig.DatastoreType{apiconfig.EtcdV3 /*, apiconfig.Kubernetes*/}, func(getInfra infrastructure.InfraFactory) {
	var (
		cgroupSubdir string
		infra        infrastructure.DatastoreInfra
		felix        *infrastructure.Felix
		host         *workload.Workload
		otherHost    *workload.Workload
		ip           string
		port         int
	)

	BeforeEach(func() {
		if err := bpf.SupportsSockmap(); err != nil {
			Skip(fmt.Sprintf("Sockmap acceleration not supported: %v", err))
		}
		cgroupSubdir = randStringRunes(8)
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.FelixLogSeverity = "debug"
		opts.ExtraEnvVars["FELIX_XDPENABLED"] = "0"
		opts.ExtraEnvVars["FELIX_SOCKMAPENABLED"] = "1"
		opts.ExtraEnvVars["FELIX_SOCKMAPCGROUPV2SUBDIR"] = cgroupSubdir
		felix, _ = infrastructure.StartSingleNodeTopology(opts, infra)
		Expect(waitForCgroupSubdir(felix, cgroupSubdir)).NotTo(HaveOccurred())
		ip = "10.65.0.2"
		port = 8055
		host = workload.Run(
			felix,
			"service",
			"default",
			ip,
			fmt.Sprintf("%d", port),
			"tcp")
		host.ConfigureInDatastore(infra)
		otherHost = workload.Run(
			felix,
			"other",
			"default",
			"10.65.0.3",
			fmt.Sprintf("%d", port),
			"tcp")
		otherHost.ConfigureInDatastore(infra)
	})

	AfterEach(func() {
		otherHost.Stop()
		host.Stop()
		felix.Stop()
		infra.Stop()
	})

	It("should put the IP of the host in sockops endpoints map", func() {
		hexen := testIPToHex(ip)
		found := false
		maxTries := 5
		log.WithFields(log.Fields{
			"ip":    ip,
			"hexen": hexen,
		}).Info("Looking for IP.")
		for try := 0; try < maxTries; try++ {
			output, err := utils.Command("docker", "exec", felix.Container.Name,
				"bpftool", "--json", "--pretty",
				"map", "dump", "pinned",
				"/sys/fs/bpf/calico/sockmap/calico_sk_endpoints_v1").CombinedOutput()
			log.WithField("output", string(output)).Info("did dump of calico_sk_endpoints_v1")
			Expect(err).NotTo(HaveOccurred())
			var entry []mapEntry
			err = json.Unmarshal(output, &entry)
			Expect(err).NotTo(HaveOccurred())
			log.WithField("entry", entry).Info("Checking map entry")
			for _, l := range entry {
				if strSliceEqual(l.Key, hexen) {
					found = true
				}
			}
			if found {
				break
			} else if try+1 < maxTries {
				time.Sleep(500 * time.Millisecond)
			}
		}
		Expect(found).To(BeTrue())
	})
})
