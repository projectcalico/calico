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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

func prepend0xInPlace(hexen []string) {
	for idx := range hexen {
		hexen[idx] = "0x" + hexen[idx]
	}
}

func getSockmapKeys(ip string, port int) [][]string {
	key := make([]byte, 12)
	parsedIP := net.ParseIP(ip)
	Expect(parsedIP).NotTo(BeNil())
	parsedIP = parsedIP.To4()
	Expect(parsedIP).NotTo(BeNil())
	copy(key, parsedIP)
	binary.BigEndian.PutUint16(key[4:], uint16(port))
	key2 := make([]byte, 12)
	copy(key2, key)
	binary.LittleEndian.PutUint32(key2[8:], 1)
	strKeys := make([][]string, 0, 2)
	for _, k := range [][]byte{key, key2} {
		strKey := make([]string, 0, 12)
		for _, b := range k {
			strKey = append(strKey, fmt.Sprintf("%02x", b))
		}
		prepend0xInPlace(strKey)
		strKeys = append(strKeys, strKey)
	}
	return strKeys
}

func testIPToHex(ip string) []string {
	cidr := fmt.Sprintf("%s/32", ip)
	hexen, err := bpf.CidrToHex(cidr)
	Expect(err).NotTo(HaveOccurred())
	prepend0xInPlace(hexen)
	return hexen
}

func checkEndpointIP(felix *infrastructure.Felix, ip string) bool {
	hexen := testIPToHex(ip)
	log.WithFields(log.Fields{
		"ip":    ip,
		"hexen": hexen,
	}).Info("Looking for IP.")
	output, err := utils.Command(
		"docker",
		"exec",
		felix.Container.Name,
		"bpftool",
		"--json",
		"--pretty",
		"map",
		"dump",
		"pinned",
		"/sys/fs/bpf/calico/sockmap/calico_sk_endpoints_v1",
	).CombinedOutput()
	log.WithField("output", string(output)).Info("Dump of calico_sk_endpoints_v1")
	Expect(err).NotTo(HaveOccurred())
	var entries []mapEntry
	Expect(json.Unmarshal(output, &entries)).NotTo(HaveOccurred())
	log.WithField("entries", entries).Info("Checking map entry")
	for _, entry := range entries {
		if strSliceEqual(entry.Key, hexen) {
			return true
		}
	}
	return false
}

// unmarshalBpfToolSockhashDumpOutput parses the normal, non-JSON
// bpftool output, because the JSON output for a command we care about
// is broken. It's fixed upstream, but we still use the old version.
func unmarshalBpfToolSockhashDumpOutput(output []byte) []mapEntry {
	var al []mapEntry
	buf := bytes.NewBuffer(output)
	// 0 - "key:", 1: actual key, 2: "value:", 3: actual value
	phase := 0
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			return al
		}
		line = strings.TrimSpace(line)
		if phase == 0 && strings.HasPrefix(line, "Found ") {
			return al
		}
		if phase == 1 {
			fields := strings.Fields(line)
			prepend0xInPlace(fields)
			entry := mapEntry{
				Key: fields,
			}
			al = append(al, entry)
		}
		phase = (phase + 1) % 4
	}
}

func getSockmapOpts() infrastructure.TopologyOptions {
	opts := infrastructure.DefaultTopologyOptions()
	opts.EnableIPv6 = false
	opts.FelixLogSeverity = "debug"
	opts.ExtraEnvVars["FELIX_XDPENABLED"] = "0"
	opts.ExtraEnvVars["FELIX_SIDECARACCELERATIONENABLED"] = "1"
	return opts
}

func sockmapTestLockFile() string {
	return filepath.Join(os.TempDir(), "SOCKMAP_FV_TEST.lock")
}

// lockSockmapTest acquires a simple file-based lock using the
// O_CREATE | O_EXCL flags
func lockSockmapTest() {
	n := sockmapTestLockFile()
	dir := filepath.Dir(n)
	log.WithFields(log.Fields{
		"dir":      dir,
		"lockfile": n,
	}).Info("About to lock")
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.WithFields(log.Fields{
			"dir":      dir,
			"lockfile": n,
		}).WithError(err).Warn("Failed to create a directory for a lock file")
		return
	}
	log.WithFields(log.Fields{
		"dir":      dir,
		"lockfile": n,
	}).Info("Dir for lock is there")
	for {
		f, err := os.OpenFile(n, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0640)
		if err == nil {
			log.WithFields(log.Fields{
				"dir":      dir,
				"lockfile": n,
			}).Info("Lock acquired successfully")
			f.Close()
			return
		}
		if !os.IsExist(err) {
			log.WithFields(log.Fields{
				"lockfile": n,
			}).WithError(err).Warn("Failed to create a lock file")
			return
		}
		log.WithFields(log.Fields{
			"dir":      dir,
			"lockfile": n,
		}).Info("Lock in place, sleeping 1 second")
		time.Sleep(time.Second)
	}
}

func unlockSockmapTest() {
	n := sockmapTestLockFile()
	log.WithFields(log.Fields{
		"lockfile": n,
	}).Info("About to unlock")
	if err := os.Remove(n); err != nil {
		log.WithFields(log.Fields{
			"lockfile": n,
		}).WithError(err).Info("Failed to remove a lock file")
		return
	}
	log.WithFields(log.Fields{
		"lockfile": n,
	}).Info("Unlocked successfully")
}

var _ = infrastructure.DatastoreDescribe("[SOCKMAP] with Felix using sockmap", []apiconfig.DatastoreType{apiconfig.EtcdV3 /*, apiconfig.Kubernetes*/}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra   infrastructure.DatastoreInfra
		felix   *infrastructure.Felix
		host    *workload.Workload
		ip      string
		port    int
		srcPort int
	)

	BeforeEach(func() {
		if err := bpf.SupportsSockmap(); err != nil {
			Skip(fmt.Sprintf("Sockmap acceleration not supported: %v", err))
		}
		lockSockmapTest()
		// This is to try to avoid having a stale lock when
		// something in BeforeEach fails and panics. We set
		// unlockAtEnd to false at the end of this
		// function. So in case of everything working just
		// fine, the lock is removed in the AfterEach
		// function.
		unlockAtEnd := true
		defer func() {
			if unlockAtEnd {
				unlockSockmapTest()
			}
		}()
		infra = getInfra()
		opts := getSockmapOpts()
		felix, _ = infrastructure.StartSingleNodeTopology(opts, infra)
		ip = "10.65.0.2"
		port = 8055
		srcPort = 8056
		host = workload.Run(
			felix,
			"service",
			"default",
			ip,
			fmt.Sprintf("%d", port),
			"tcp")
		host.ConfigureInDatastore(infra)
		unlockAtEnd = false
	})

	AfterEach(func() {
		defer unlockSockmapTest()
		host.Stop()
		felix.Stop()
		func() {
			opts := getSockmapOpts()
			felix, _ = infrastructure.StartSingleNodeTopology(opts, infra)
			defer felix.Stop()
			outputBytes, err := utils.Command(
				"docker",
				"exec",
				felix.Container.Name,
				"bpftool",
				"--json",
				"--pretty",
				"map",
				"dump",
				"pinned",
				"/sys/fs/bpf/calico/sockmap/calico_sock_map_v1",
			).CombinedOutput()
			if err != nil {
				log.WithFields(log.Fields{
					"containerID": felix.Container.Name,
					"output":      string(outputBytes),
				}).WithError(err).Info("Failed to dump the contents of the sock map, skipping cleanup")
				return
			}
			if strings.TrimSpace(string(outputBytes)) != "[]" {
				log.WithFields(log.Fields{
					"containerID": felix.Container.Name,
					"output":      string(outputBytes),
				}).Info("Sock map is not empty, skipping cleanup")
				return
			}
			fullCgroupDir := "/run/calico/cgroup"
			outputBytes, err = utils.Command(
				"docker",
				"exec",
				felix.Container.Name,
				"bpftool",
				"cgroup",
				"detach",
				fullCgroupDir,
				"sock_ops",
				"pinned",
				"/sys/fs/bpf/calico/sockmap/calico_sockops_v1",
			).CombinedOutput()
			if err != nil {
				log.WithFields(log.Fields{
					"cgroupdir":   fullCgroupDir,
					"containerID": felix.Container.Name,
					"output":      string(outputBytes),
				}).WithError(err).Info("Failed to detach sockops program from cgroup, skipping cleanup")
				return
			}
			log.Info("Cleanup finished")
		}()
		infra.Stop()
	})

	It("should put the IP of the host in sockmap endpoints map", func() {
		found := false
		maxTries := 5
		for try := 0; try < maxTries; try++ {
			found = checkEndpointIP(felix, ip)
			if found {
				break
			} else if try+1 < maxTries {
				time.Sleep(500 * time.Millisecond)
			}
		}
		Expect(found).To(BeTrue())
	})

	It("should establish sockmap acceleration", func() {
		{
			found := false
			maxTries := 5
			for try := 0; try < maxTries; try++ {
				found = checkEndpointIP(felix, ip)
				if found {
					break
				} else if try+1 < maxTries {
					time.Sleep(500 * time.Millisecond)
				}
			}
			Expect(found).To(BeTrue())
		}
		side := host.StartSideService()
		defer side.Stop()
		pc := host.StartPermanentConnection("1.1.1.1", 80, srcPort)
		defer pc.Stop()
		maxTries := 5
		keys := getSockmapKeys(ip, srcPort)
		foundKeys := make([]int, len(keys))
		foundAll := false
		for i := 0; i < maxTries; i++ {
			output, err := utils.Command(
				"docker",
				"exec",
				felix.Container.Name,
				"bpftool",
				"map",
				"dump",
				"pinned",
				"/sys/fs/bpf/calico/sockmap/calico_sock_map_v1",
			).CombinedOutput()
			log.WithField("output", string(output)).Info("Dump of calico_sock_map_v1")
			Expect(err).NotTo(HaveOccurred())
			al := unmarshalBpfToolSockhashDumpOutput(output)
			log.WithFields(log.Fields{
				"keys":    keys,
				"entries": al,
			}).Info("Checking contents of calico_sock_map_v1")
			for _, l := range al {
				for idx, key := range keys {
					if strSliceEqual(l.Key, key) {
						foundKeys[idx]++
					}
				}
			}
			foundAll = true
			for _, found := range foundKeys {
				if found != 1 {
					foundAll = false
					break
				}
			}
			if foundAll {
				break
			} else {
				time.Sleep(500 * time.Millisecond)
			}
		}
		Expect(foundAll).To(BeTrue())
	})
})
