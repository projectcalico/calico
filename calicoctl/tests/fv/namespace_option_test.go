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
	"testing"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/calicoctl/tests/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	log.AddHook(logutils.ContextHook{})
	log.SetFormatter(&logutils.Formatter{})
}

func TestMultiOption(t *testing.T) {
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
	defer func() {
		_, err = client.IPPools().Delete(ctx, "ipam-test-v4", options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}()

	np := v3.NewNetworkPolicy()
	np.Name = "policy1"
	np.Namespace = "firstns"
	_, err = client.NetworkPolicies().Create(ctx, np, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		_, err = client.NetworkPolicies().Delete(ctx, "firstns", "policy1", options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}()

	np.Name = "policy2"
	np.Namespace = "secondns"
	_, err = client.NetworkPolicies().Create(ctx, np, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
	defer func() {
		_, err = client.NetworkPolicies().Delete(ctx, "secondns", "policy2", options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	}()

	// Set Calico version in ClusterInformation
	out, err := SetCalicoVersion(false)
	Expect(err).ToNot(HaveOccurred())
	Expect(out).To(ContainSubstring("Calico version set to"))

	out, err = CalicoctlMayFail(false, "get", "ippool", "-A")
	Expect(err).To(HaveOccurred())
	Expect(out).To(Equal("IPPool is not namespaced\n"))

	out, err = CalicoctlMayFail(false, "get", "ippool", "-a")
	Expect(err).To(HaveOccurred())
	Expect(out).To(Equal("IPPool is not namespaced\n"))

	out = Calicoctl(false, "get", "networkPolicy", "-A")
	Expect(out).To(Equal("NAMESPACE   NAME      \nfirstns     policy1   \nsecondns    policy2   \n\n"))

	out = Calicoctl(false, "get", "networkPolicy", "-a")
	Expect(out).To(Equal("NAMESPACE   NAME      \nfirstns     policy1   \nsecondns    policy2   \n\n"))
}
