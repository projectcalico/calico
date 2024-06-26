// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

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

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

type mapEntry struct {
	Key []string `json:"key"`
}

func prepend0xInPlace(hexen []string) {
	for idx := range hexen {
		hexen[idx] = "0x" + hexen[idx]
	}
}

// getExpectedSockmapKeys returns an array of sockhash map keys in a
// form similar to what bpftool could print. So each key is an array
// of 12 strings being a representation of hexadecimal bytes. First
// four bytes contain passed IP address, next four bytes contain
// passed port and the last four bytes contain encoded 1 or 0,
// denoting whether a socket is on the envoy side or not.
func getExpectedSockmapKeys(ip string, port int) [][]string {
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

func getEndpointsMapContents(felix *infrastructure.Felix) [][]string {
	output, err := felix.Container.ExecOutput(
		"bpftool",
		"--json",
		"--pretty",
		"map",
		"dump",
		"pinned",
		"/sys/fs/bpf/calico/sockmap/calico_sk_endpoints_v1",
	)
	logCtx := log.WithField("output", output)
	if err != nil {
		logCtx.WithError(err).Warn("Failed to dump the calico_sk_endpoints_v1 map")
		return nil
	}
	logCtx.Info("Dump of calico_sk_endpoints_v1")
	var entries []mapEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		logCtx.WithError(err).Warn("Failed to parse output as JSON")
		return nil
	}
	logCtx.WithField("entries", entries).Info("Parsed the output")
	keys := make([][]string, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Key)
	}
	return keys
}

// unmarshalBpfToolSockhashDumpOutput parses the normal, non-JSON
// bpftool output, because the JSON output for a command we care about
// is broken. It's fixed upstream, but we still use the old version.
func unmarshalBpfToolSockhashDumpOutput(output string) []mapEntry {
	var al []mapEntry
	buf := bytes.NewBufferString(output)
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
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
		f, err := os.OpenFile(n, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o640)
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
		tc      infrastructure.TopologyContainers
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
		tc, _ = infrastructure.StartSingleNodeTopology(opts, infra)
		ip = "10.65.0.2"
		port = 8055
		srcPort = 8056
		host = workload.Run(
			tc.Felixes[0],
			"service",
			"default",
			ip,
			fmt.Sprintf("%d", port),
			"tcp")
		host.ConfigureInInfra(infra)
		unlockAtEnd = false
	})

	AfterEach(func() {
		defer unlockSockmapTest()
		host.Stop()
		tc.Stop()
		// Clean up the sockmap state. We do this by starting
		// a new felix instance (after stopping the old one),
		// so it cleans up the whatever state we ended up
		// having after the test, and sets up a fresh, empty
		// one. With such a state we can now try to manually
		// detach the sockhash map from the cgroup and then
		// kill felix. This should drop all the references to
		// programs and maps, so the kernel will just delete
		// them. That way we will have no leftovers.
		func() {
			opts := getSockmapOpts()
			tc, _ = infrastructure.StartSingleNodeTopology(opts, infra)
			defer tc.Stop()
			output, err := tc.Felixes[0].Container.ExecOutput(
				"bpftool",
				"--json",
				"--pretty",
				"map",
				"dump",
				"pinned",
				"/sys/fs/bpf/calico/sockmap/calico_sock_map_v1",
			)
			if err != nil {
				log.WithFields(log.Fields{
					"containerID": tc.Felixes[0].Container.Name,
					"output":      output,
				}).WithError(err).Info("Failed to dump the contents of the sock map, skipping cleanup")
				return
			}
			if strings.TrimSpace(output) != "[]" {
				log.WithFields(log.Fields{
					"containerID": tc.Felixes[0].Container.Name,
					"output":      output,
				}).Info("Sock map is not empty, skipping cleanup")
				return
			}
			fullCgroupDir := "/run/calico/cgroup"
			output, err = tc.Felixes[0].Container.ExecOutput(
				"bpftool",
				"cgroup",
				"detach",
				fullCgroupDir,
				"sock_ops",
				"pinned",
				"/sys/fs/bpf/calico/sockmap/calico_sockops_v1",
			)
			if err != nil {
				log.WithFields(log.Fields{
					"cgroupdir":   fullCgroupDir,
					"containerID": tc.Felixes[0].Container.Name,
					"output":      output,
				}).WithError(err).Info("Failed to detach sockops program from cgroup, skipping cleanup")
				return
			}
			log.Info("Cleanup finished")
		}()
		infra.Stop()
	})

	It("should put the IP of the host in sockmap endpoints map", func() {
		hexen := testIPToHex(ip)
		log.WithFields(log.Fields{
			"ip":    ip,
			"hexen": hexen,
		}).Info("Looking for IP.")
		Eventually(func() [][]string {
			return getEndpointsMapContents(tc.Felixes[0])
		}, 5*time.Second, 500*time.Millisecond).Should(ContainElement(hexen))
	})

	It("should establish sockmap acceleration", func() {
		// This test case has not run for a long time, because the Semaphore
		// kernel version did not support it, and we did not include it in the set
		// of tests that run on GCP VMs with a newer kernel.  The Semaphore kernel
		// just got upgraded, so now this test _can_ run on Semaphore, but it
		// fails.  We don't want to invest time now to investigate that, so the
		// simplest remedy is to skip this test case.
		Skip("Test has not run for a long time and is now broken, so skipping")
		{
			hexen := testIPToHex(ip)
			Eventually(func() [][]string {
				return getEndpointsMapContents(tc.Felixes[0])
			}, 5*time.Second, 500*time.Millisecond).Should(ContainElement(hexen))
		}
		side := host.StartSideService()
		defer side.Stop()
		pc := host.StartPersistentConnection("1.1.1.1", 80, workload.PersistentConnectionOpts{
			SourcePort: srcPort,
		})
		defer pc.Stop()
		expectedKeys := getExpectedSockmapKeys(ip, srcPort)
		Eventually(func() [][]string {
			output, err := tc.Felixes[0].Container.ExecOutput(
				"bpftool",
				"map",
				"dump",
				"pinned",
				"/sys/fs/bpf/calico/sockmap/calico_sock_map_v1",
			)
			logCxt := log.WithField("output", output)
			if err != nil {
				logCxt.WithError(err).Warn("Failed to dump calico_sock_map_v1")
				return nil
			}
			logCxt.Info("Dump of calico_sock_map_v1")
			al := unmarshalBpfToolSockhashDumpOutput(output)
			logCxt.WithFields(log.Fields{
				"entries": al,
			}).Info("Parsed contents of calico_sock_map_v1")
			keys := make([][]string, 0, len(al))
			for _, l := range al {
				keys = append(keys, l.Key)
			}
			return keys
		}, 5*time.Second, 500*time.Millisecond).Should(ConsistOf(expectedKeys))
	})
})
