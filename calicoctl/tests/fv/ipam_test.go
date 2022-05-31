// Copyright (c) 2019,2021 Tigera, Inc. All rights reserved.

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

package fv_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	log "github.com/sirupsen/logrus"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	ipamcmd "github.com/projectcalico/calico/calicoctl/calicoctl/commands/ipam"
	. "github.com/projectcalico/calico/calicoctl/tests/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	log.AddHook(logutils.ContextHook{})
	log.SetFormatter(&logutils.Formatter{})
}

func TestIPAM(t *testing.T) {
	RegisterTestingT(t)

	ctx := context.Background()

	// Create a Calico client.
	config := apiconfig.NewCalicoAPIConfig()
	config.Spec.DatastoreType = "etcdv3"
	config.Spec.EtcdEndpoints = "http://127.0.0.1:2379"
	client, err := clientv3.New(*config)
	Expect(err).NotTo(HaveOccurred())

	// Create an IPv4 pool.
	pool := v3.NewIPPool()
	pool.Name = "ipam-test-v4"
	pool.Spec.CIDR = "10.65.0.0/16"
	_, err = client.IPPools().Create(ctx, pool, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())

	// Create an IPv6 pool.
	pool = v3.NewIPPool()
	pool.Name = "ipam-test-v6"
	pool.Spec.CIDR = "fd5f:abcd:64::0/48"
	_, err = client.IPPools().Create(ctx, pool, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())

	// Create a Node resource for this host.
	node := libapi.NewNode()
	node.Name, err = os.Hostname()
	Expect(err).NotTo(HaveOccurred())
	_, err = client.Nodes().Create(ctx, node, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())

	// Set Calico version in ClusterInformation
	out, err := SetCalicoVersion(false)
	Expect(err).ToNot(HaveOccurred())
	Expect(out).To(ContainSubstring("Calico version set to"))

	// ipam show with specific unallocated IP.
	out = Calicoctl(false, "ipam", "show", "--ip=10.65.0.2")
	Expect(out).To(ContainSubstring("10.65.0.2 is not assigned"))

	// ipam show, with no allocations yet.
	out = Calicoctl(false, "ipam", "show")
	Expect(out).To(ContainSubstring("IPS IN USE"))

	// Assign some IPs.
	var v4, v6 []cnet.IPNet
	v4Assignments, v6Assignments, err := client.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
		Num4:        5,
		Num6:        7,
		Attrs:       map[string]string{"note": "reserved by ipam_test.go"},
		IntendedUse: v3.IPPoolAllowedUseWorkload,
	})
	Expect(err).NotTo(HaveOccurred())
	if v4Assignments != nil {
		v4 = v4Assignments.IPs
	}
	if v6Assignments != nil {
		v6 = v6Assignments.IPs
	}

	// ipam show, pools only.
	out = Calicoctl(false, "ipam", "show")
	Expect(out).To(ContainSubstring("IPS IN USE"))
	Expect(out).To(ContainSubstring("10.65.0.0/16"))
	Expect(out).To(ContainSubstring("5 (0%)"))
	Expect(out).To(ContainSubstring("65531 (100%)"))
	Expect(out).To(ContainSubstring("fd5f:abcd:64::/48"))

	// ipam show, including blocks.
	out = Calicoctl(false, "ipam", "show", "--show-blocks")
	Expect(out).To(ContainSubstring("Block"))
	Expect(out).To(ContainSubstring("5 (8%)"))
	Expect(out).To(ContainSubstring("59 (92%)"))

	// Find out the allocation block.
	var allocatedIP string
	r, err := regexp.Compile(`(10\.65\.[0-9]+\.)([0-9]+)/26`)
	Expect(err).NotTo(HaveOccurred())
	for _, line := range strings.Split(out, "\n") {
		sm := r.FindStringSubmatch(line)
		if len(sm) > 0 {
			ordinalBase, err := strconv.Atoi(sm[2])
			Expect(err).NotTo(HaveOccurred())
			allocatedIP = sm[1] + strconv.Itoa(ordinalBase+2)
			break
		}
	}
	Expect(allocatedIP).NotTo(BeEmpty())

	// ipam show with specific IP that is now allocated.
	out = Calicoctl(false, "ipam", "show", "--ip="+allocatedIP)
	Expect(out).To(ContainSubstring(allocatedIP + " is in use"))
	Expect(out).To(ContainSubstring("Attributes:"))
	Expect(out).To(ContainSubstring("note: reserved by ipam_test.go"))

	// ipam show with an invalid IP.
	out, err = CalicoctlMayFail(false, "ipam", "show", "--ip=10.240.0.300")
	Expect(err).To(HaveOccurred())
	Expect(out).To(ContainSubstring("invalid IP address"))

	// Create a pool with blocksize 29, so we can easily allocate
	// an entire block.
	pool = v3.NewIPPool()
	pool.Name = "ipam-test-v4-b29"
	pool.Spec.CIDR = "10.66.0.0/16"
	pool.Spec.BlockSize = 29
	_, err = client.IPPools().Create(ctx, pool, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())

	// Allocate more than one block's worth (8) of IPs from that
	// pool.
	// Assign some IPs.
	var v4More, v6More []cnet.IPNet
	v4MoreAssignments, v6MoreAssignments, err := client.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
		Num4:        11,
		IPv4Pools:   []cnet.IPNet{cnet.MustParseNetwork(pool.Spec.CIDR)},
		IntendedUse: v3.IPPoolAllowedUseWorkload,
	})
	Expect(err).NotTo(HaveOccurred())
	if v4MoreAssignments != nil {
		v4More = v4MoreAssignments.IPs
	}
	if v6MoreAssignments != nil {
		v6More = v6MoreAssignments.IPs
	}

	// ipam show, including blocks.
	//
	// Example output here:
	// +----------+-------------------------------------------+------------+------------+-------------------+
	// | GROUPING |                   CIDR                    | IPS TOTAL  | IPS IN USE |     IPS FREE      |
	// +----------+-------------------------------------------+------------+------------+-------------------+
	// | IP Pool  | 10.65.0.0/16                              |      65536 | 5 (0%)     | 65531 (100%)      |
	// | Block    | 10.65.79.0/26                             |         64 | 5 (8%)     | 59 (92%)          |
	// | IP Pool  | 10.66.0.0/16                              |      65536 | 11 (0%)    | 65525 (100%)      |
	// | Block    | 10.66.137.224/29                          |          8 | 8 (100%)   | 0 (0%)            |
	// | Block    | 10.66.137.232/29                          |          8 | 3 (38%)    | 5 (62%)           |
	// | IP Pool  | fd5f:abcd:64::/48                         | 1.2089e+24 | 7 (0%)     | 1.2089e+24 (100%) |
	// | Block    | fd5f:abcd:64:4f2c:ec1b:27b9:1989:77c0/122 |         64 | 7 (11%)    | 57 (89%)          |
	// +----------+-------------------------------------------+------------+------------+-------------------+
	outLines := strings.Split(Calicoctl(false, "ipam", "show", "--show-blocks"), "\n")
	Expect(outLines).To(ContainElement(And(ContainSubstring("Block"), ContainSubstring("10.66"), ContainSubstring("8 (100%)"), ContainSubstring("0 (0%)"))))
	Expect(outLines).To(ContainElement(And(ContainSubstring("IP Pool"), ContainSubstring("fd5f"), ContainSubstring("7 (0%)"))))

	// Clean up resources
	cidrs := append(v4, v4More...)
	cidrs = append(cidrs, v6...)
	cidrs = append(cidrs, v6More...)
	nodename, err := os.Hostname()
	Expect(err).NotTo(HaveOccurred())
	var ips []ipam.ReleaseOptions
	for _, cidr := range cidrs {
		err = client.IPAM().ReleaseAffinity(ctx, cidr, nodename, false)
		Expect(err).NotTo(HaveOccurred())
		ip := cnet.ParseIP(cidr.IP.String())
		ips = append(ips, ipam.ReleaseOptions{Address: ip.IP.String()})
	}
	// Release the IPs
	_, err = client.IPAM().ReleaseIPs(ctx, ips...)
	Expect(err).NotTo(HaveOccurred())

	_, err = client.IPPools().Delete(ctx, "ipam-test-v4", options.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = client.IPPools().Delete(ctx, "ipam-test-v6", options.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = client.Nodes().Delete(ctx, nodename, options.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = client.IPPools().Delete(ctx, "ipam-test-v4-b29", options.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func TestIPAMCleanup(t *testing.T) {
	RegisterTestingT(t)

	ctx := context.Background()

	// Create a Calico client.
	config := apiconfig.NewCalicoAPIConfig()
	config.Spec.DatastoreType = "etcdv3"
	config.Spec.EtcdEndpoints = "http://127.0.0.1:2379"
	client, err := clientv3.New(*config)
	Expect(err).NotTo(HaveOccurred())

	// Set Calico version in ClusterInformation
	out, err := SetCalicoVersion(false)
	Expect(err).ToNot(HaveOccurred())
	Expect(out).To(ContainSubstring("Calico version set to"))

	// Create an IPv4 pool.
	pool := v3.NewIPPool()
	pool.Name = "ipam-test-v4-handle-clean"
	pool.Spec.CIDR = "10.66.0.0/16"
	_, err = client.IPPools().Create(ctx, pool, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())

	defer func() {
		_, err = client.IPPools().Delete(ctx, "ipam-test-v4-handle-clean", options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}()

	// Create a Node resource for this host.
	node := libapi.NewNode()
	node.Name, err = os.Hostname()
	Expect(err).NotTo(HaveOccurred())
	_, err = client.Nodes().Create(ctx, node, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		_, err = client.Nodes().Delete(ctx, node.Name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}()

	// Assign some IPs.
	myHandle := "TestIPAMCleanup"
	v4Assignments, _, err := client.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
		Num4:        1,
		Attrs:       map[string]string{"note": "reserved by ipam_test.go"},
		HandleID:    &myHandle,
		IntendedUse: v3.IPPoolAllowedUseWorkload,
	})
	_ = v4Assignments
	Expect(err).NotTo(HaveOccurred())

	// Make a raw, leaked handle for IPAM check to find.
	type accessor interface {
		Backend() bapi.Client
	}
	bc := client.(accessor).Backend()
	createLeakedHandle := func() *model.KVPair {
		kv, err := bc.Create(ctx, &model.KVPair{
			Key: model.IPAMHandleKey{
				HandleID: "leaked-handle",
			},
			Value: &model.IPAMHandle{
				HandleID: "leaked-handle",
				Block: map[string]int{
					"10.65.79.0/26": 1,
				},
				Deleted: false,
			},
		})
		Expect(err).NotTo(HaveOccurred())
		return kv
	}
	createLeakedHandle()

	// Run calicoctl ipam check and parse the resulting report.
	out = Calicoctl(false, "ipam", "check", "--show-all-ips", "-o", "/tmp/ipam_report.json")
	t.Log("IPAM check output:", out)
	reportFile, err := ioutil.ReadFile("/tmp/ipam_report.json")
	Expect(err).NotTo(HaveOccurred())
	t.Log("IPAM check report (raw JSON):", string(reportFile))
	var report ipamcmd.Report
	err = json.Unmarshal(reportFile, &report)
	Expect(err).NotTo(HaveOccurred())

	// Check that handles were reported correctly.
	Expect(out).To(ContainSubstring("Found 1 handles with no matching IPs (and 1 handles with matches)."))
	Expect(report.LeakedHandles).To(HaveLen(1))
	Expect(report.LeakedHandles[0].ID).To(Equal("leaked-handle"))
	Expect(report.LeakedHandles[0].Revision).ToNot(BeEmpty())

	out, err = CalicoctlMayFail(false, "ipam", "release", "--from-report=/tmp/ipam_report.json")
	Expect(err).To(HaveOccurred(), "calicoctl ipam release should fail if datastore is not locked")
	Expect(out).To(ContainSubstring("not locked"))

	out, err = CalicoctlMayFail(false, "ipam", "release", "--from-report=/tmp/ipam_report.json", "--force")
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to run calicoctl ipam release: %s", out))
	t.Log("calicoctl ipam release output:", out)
	Expect(out).To(ContainSubstring("Released 1 IPs successfully"))
	Expect(out).To(ContainSubstring("Released 1 handles; skipped 0 (already gone); 0 skipped (handle updated since report); 0 errors."))

	// Both handles should now be gone.
	handles, err := bc.List(ctx, model.IPAMHandleListOptions{}, "")
	Expect(err).NotTo(HaveOccurred())
	for _, kv := range handles.KVPairs {
		hk := kv.Key.(model.IPAMHandleKey)
		Expect(hk.HandleID).NotTo(Equal("leaked-handle"))
		Expect(hk.HandleID).NotTo(Equal(myHandle))
	}
}
