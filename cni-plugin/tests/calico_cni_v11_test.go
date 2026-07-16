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

package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/testutils"
)

// Tests for the CNI spec v1.1.0 verbs (STATUS, GC). These pin their own
// "cniVersion": "1.1.0" rather than using the suite-wide CNI_SPEC_VERSION,
// since the new verbs are only valid at 1.1.0.
var _ = Describe("CNI spec v1.1 verbs", func() {
	BeforeEach(func() {
		// Wipes the datastore and seeds ClusterInformation with
		// datastoreReady=true, which STATUS requires.
		testutils.WipeDatastore()
	})

	netconf := fmt.Sprintf(`{
	  "cniVersion": "1.1.0",
	  "name": "net-status",
	  "type": "calico",
	  "etcd_endpoints": "http://%s:2379",
	  "datastore_type": "%s",
	  "log_level": "info",
	  "nodename_file_optional": true,
	  "ipam": {"type": "calico-ipam"},
	  "kubernetes": {"kubeconfig": "%s"}
	}`, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBECONFIG"))

	It("returns success when the datastore is ready", func() {
		exitCode, stdout := testutils.RunCNIVerb("calico", "STATUS", netconf, nil)
		Expect(exitCode).To(Equal(0), "STATUS failed: %s", string(stdout))
	})

	It("returns success for calico-ipam when the datastore is ready", func() {
		exitCode, stdout := testutils.RunCNIVerb("calico-ipam", "STATUS", netconf, nil)
		Expect(exitCode).To(Equal(0), "STATUS failed: %s", string(stdout))
	})

	It("accepts GC requests (stub: no cleanup performed)", func() {
		gcConf := strings.Replace(netconf, `"ipam"`,
			`"cni.dev/valid-attachments": [{"containerID": "gc-test-container", "ifname": "eth0"}], "ipam"`, 1)
		exitCode, stdout := testutils.RunCNIVerb("calico", "GC", gcConf, nil)
		Expect(exitCode).To(Equal(0), "GC failed: %s", string(stdout))
		// GC success must produce no result on stdout.
		Expect(strings.TrimSpace(string(stdout))).To(BeEmpty())
	})

	It("accepts CHECK requests (stub: no verification) with empty stdout", func() {
		exitCode, stdout := testutils.RunCNIVerb("calico", "CHECK", netconf,
			[]string{"CNI_CONTAINERID=check-test-container"})
		Expect(exitCode).To(Equal(0), "CHECK failed: %s", string(stdout))
		// CHECK success must produce no output on stdout.
		Expect(strings.TrimSpace(string(stdout))).To(BeEmpty())
	})

	It("returns CNI error code 50 when the datastore is unreachable", func() {
		if os.Getenv("DATASTORE_TYPE") != "etcdv3" {
			Skip("unreachable-datastore case is simulated via bad etcd endpoints")
		}
		badConf := strings.Replace(netconf,
			fmt.Sprintf("http://%s:2379", os.Getenv("ETCD_IP")),
			"http://10.255.255.1:5", 1)
		exitCode, stdout := testutils.RunCNIVerb("calico", "STATUS", badConf, nil)
		Expect(exitCode).NotTo(Equal(0))
		var cniErr cnitypes.Error
		Expect(json.Unmarshal(stdout, &cniErr)).To(Succeed())
		Expect(cniErr.Code).To(Equal(uint(50)))
	})
})
