// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

// +build fvtests

package fv_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"

	"github.com/projectcalico/felix/fv/connectivity"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Service network policy tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra           infrastructure.DatastoreInfra
		felixes         []*infrastructure.Felix
		client          client.Interface
		w               [3]*workload.Workload
		hostW           [3]*workload.Workload
		cc              *connectivity.Checker
		topologyOptions infrastructure.TopologyOptions
	)

	BeforeEach(func() {
		infra = getInfra()
		topologyOptions = infrastructure.DefaultTopologyOptions()
		felixes, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workloads, using that profile.  One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       net.MustParseIP(wIP),
				HandleID: &wName,
				Attrs: map[string]string{
					ipam.AttributeNode: felixes[ii].Hostname,
				},
				Hostname: felixes[ii].Hostname,
			})
			Expect(err).NotTo(HaveOccurred())

			w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "80,81", "tcp")
			w[ii].ConfigureInInfra(infra)

			hostW[ii] = workload.Run(felixes[ii], fmt.Sprintf("host%d", ii), "", felixes[ii].IP, "8055", "tcp")
		}

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
				felix.Exec("ip", "a")
			}
		}

		for _, wl := range w {
			wl.Stop()
		}
		for _, wl := range hostW {
			wl.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	It("should allow egress to a service", func() {
		// Expect basic connectivity to work.
		cc.ExpectSome(w[0], w[1].Port(80))
		cc.ExpectSome(w[0], w[1].Port(81))
		cc.ExpectSome(w[1], w[0].Port(80))
		cc.ExpectSome(w[1], w[0].Port(81))
		cc.CheckConnectivity()

		// Create a default-deny egress policy.
		defaultDenyPolicy := api.NewNetworkPolicy()
		defaultDenyPolicy.Namespace = "default"
		defaultDenyPolicy.Name = "knp.default.default-deny"
		thousand := 1000.0
		defaultDenyPolicy.Spec.Order = &thousand
		defaultDenyPolicy.Spec.Selector = "all()"
		defaultDenyPolicy.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		_, err := client.NetworkPolicies().Create(utils.Ctx, defaultDenyPolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Expect no traffic allowed.
		cc.ResetExpectations()
		cc.ExpectNone(w[0], w[1].Port(80))
		cc.ExpectNone(w[1], w[0].Port(80))
		cc.ExpectNone(w[0], w[1].Port(81))
		cc.ExpectNone(w[1], w[0].Port(81))
		cc.CheckConnectivity()

		// Create a Kubernetes EndpointSlice for a service named "w1-service" that includes
		// the endpoint information for w1.
		//
		// A service isn't required, as Felix is driven entirely off of endpoint slices.
		kc := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
		eighty := int32(80)
		tcp := v1.ProtocolTCP
		eps := &discovery.EndpointSlice{}
		eps.Name = "w1-eps"
		eps.Namespace = "default"
		eps.Labels = map[string]string{"kubernetes.io/service-name": "w1-service"}
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{
			{Addresses: []string{w[1].IP}},
		}
		eps.Ports = []discovery.EndpointPort{
			{Port: &eighty, Protocol: &tcp},
		}
		eps, err = kc.DiscoveryV1beta1().EndpointSlices("default").Create(utils.Ctx, eps, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Make sure we clean up after ourselves.
		defer func() {
			err = kc.DiscoveryV1beta1().EndpointSlices("default").Delete(utils.Ctx, eps.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}()

		// Create a network policy which allows to the service.
		allowServicePolicy := api.NewNetworkPolicy()
		allowServicePolicy.Namespace = "default"
		allowServicePolicy.Name = "allow-to-w1"
		allowServicePolicy.Spec.Order = &thousand
		allowServicePolicy.Spec.Selector = "all()"
		allowServicePolicy.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		allowServicePolicy.Spec.Egress = []api.Rule{
			{
				Action:      api.Allow,
				Destination: api.EntityRule{Services: &api.ServiceMatch{Name: "w1-service", Namespace: "default"}},
			},
		}
		_, err = client.NetworkPolicies().Create(utils.Ctx, allowServicePolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Expect traffic is allowed to the endpoint specified in the service - w1, TCP 80
		// Traffic the other direction, and to other ports should not be allowed.
		cc.ResetExpectations()
		cc.ExpectSome(w[0], w[1].Port(80))
		cc.ExpectNone(w[0], w[1].Port(81))
		cc.ExpectNone(w[1], w[0].Port(80))
		cc.ExpectNone(w[1], w[0].Port(81))
		cc.CheckConnectivity()

		// Update the endpoint slice to include the address of w0. Traffic should then be allowed in the reverse direction,
		// but still only to port 80.
		eps.Endpoints = append(eps.Endpoints, discovery.Endpoint{Addresses: []string{w[0].IP}})
		_, err = kc.DiscoveryV1beta1().EndpointSlices("default").Update(utils.Ctx, eps, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())
		cc.ResetExpectations()
		cc.ExpectSome(w[0], w[1].Port(80))
		cc.ExpectNone(w[0], w[1].Port(81))
		cc.ExpectSome(w[1], w[0].Port(80))
		cc.ExpectNone(w[1], w[0].Port(81))
		cc.CheckConnectivity()

		// Delete the policy. Traffic should no longer be allowed.
		_, err = client.NetworkPolicies().Delete(utils.Ctx, "default", allowServicePolicy.Name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		cc.ResetExpectations()
		cc.ExpectNone(w[0], w[1].Port(80))
		cc.ExpectNone(w[1], w[0].Port(80))
		cc.ExpectNone(w[0], w[1].Port(81))
		cc.ExpectNone(w[1], w[0].Port(81))
		cc.CheckConnectivity()
	})

	It("should deny egress to a service", func() {
		// Expect basic connectivity to work.
		cc.ExpectSome(w[0], w[1].Port(80))
		cc.ExpectSome(w[0], w[1].Port(81))
		cc.ExpectSome(w[1], w[0].Port(80))
		cc.ExpectSome(w[1], w[0].Port(81))
		cc.CheckConnectivity()

		// Create a Kubernetes EndpointSlice for a service named "w1-service" that includes
		// the endpoint information for w1.
		//
		// A service isn't required, as Felix is driven entirely off of endpoint slices.
		kc := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
		eighty := int32(80)
		tcp := v1.ProtocolTCP
		eps := &discovery.EndpointSlice{}
		eps.Name = "w1-eps"
		eps.Namespace = "default"
		eps.Labels = map[string]string{"kubernetes.io/service-name": "w1-service"}
		eps.AddressType = discovery.AddressTypeIPv4
		eps.Endpoints = []discovery.Endpoint{
			{Addresses: []string{w[1].IP}},
		}
		eps.Ports = []discovery.EndpointPort{
			{Port: &eighty, Protocol: &tcp},
		}
		_, err := kc.DiscoveryV1beta1().EndpointSlices("default").Create(utils.Ctx, eps, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Make sure we clean up after ourselves.
		defer func() {
			err = kc.DiscoveryV1beta1().EndpointSlices("default").Delete(utils.Ctx, eps.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		}()

		// Create a network policy which denies to the service, but allows elsewhere.
		thousand := 1000.0
		allowServicePolicy := api.NewNetworkPolicy()
		allowServicePolicy.Namespace = "default"
		allowServicePolicy.Name = "allow-to-w1"
		allowServicePolicy.Spec.Order = &thousand
		allowServicePolicy.Spec.Selector = "all()"
		allowServicePolicy.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		allowServicePolicy.Spec.Egress = []api.Rule{
			{
				Action:      api.Deny,
				Destination: api.EntityRule{Services: &api.ServiceMatch{Name: "w1-service", Namespace: "default"}},
			},
			{
				Action: api.Allow,
			},
		}
		_, err = client.NetworkPolicies().Create(utils.Ctx, allowServicePolicy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Expect traffic is denied to the endpoint specified in the service - w1, TCP 80
		// Traffic the other direction, and to other ports should be allowed.
		cc.ResetExpectations()
		cc.ExpectNone(w[0], w[1].Port(80))
		cc.ExpectSome(w[0], w[1].Port(81))
		cc.ExpectSome(w[1], w[0].Port(80))
		cc.ExpectSome(w[1], w[0].Port(81))
		cc.CheckConnectivity()
	})
})
