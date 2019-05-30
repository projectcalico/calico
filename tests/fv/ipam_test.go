// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"os"
	"regexp"
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calicoctl/tests/fv/utils"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/options"
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
	node := v3.NewNode()
	node.Name, err = os.Hostname()
	Expect(err).NotTo(HaveOccurred())
	_, err = client.Nodes().Create(ctx, node, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())

	// ipam show with specific unallocated IP.
	out := Calicoctl("ipam", "show", "--ip=10.65.0.2")
	Expect(out).To(ContainSubstring("10.65.0.2 is not assigned"))

	// ipam show, with no allocations yet.
	out = Calicoctl("ipam", "show")
	Expect(out).To(ContainSubstring("IPS IN USE"))

	// Assign some IPs.
	client.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{Num4: 5, Num6: 7})

	// ipam show, pools only.
	out = Calicoctl("ipam", "show")
	Expect(out).To(ContainSubstring("IPS IN USE"))
	Expect(out).To(ContainSubstring("10.65.0.0/16"))
	Expect(out).To(ContainSubstring("5/64 (8%)"))
	Expect(out).To(ContainSubstring("7/64 (11%)"))

	// ipam show, including blocks.
	out = Calicoctl("ipam", "show", "--show-blocks")
	Expect(out).To(ContainSubstring("IPS IN USE"))
	Expect(out).To(ContainSubstring("Block"))
	Expect(out).To(ContainSubstring("5/64 (8%)"))

	// Find out the allocation block.
	var allocationBlock string
	r, err := regexp.Compile("10\\.65\\.[0-9]+")
	Expect(err).NotTo(HaveOccurred())
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Block") {
			continue
		}
		allocationBlock = r.FindString(line)
		if allocationBlock != "" {
			break
		}
	}
	Expect(allocationBlock).NotTo(BeEmpty())

	// ipam show with specific IP that is now allocated.
	allocatedIP := allocationBlock + ".2"
	out = Calicoctl("ipam", "show", "--ip="+allocatedIP)
	Expect(out).To(ContainSubstring(allocatedIP + " is in use"))
}
