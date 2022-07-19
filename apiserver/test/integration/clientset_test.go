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
// limitations under the License.package util

package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
)

// TestGroupVersion is trivial.
func TestGroupVersion(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkPolicy{}
			})
			defer shutdownServer()
			if err := testGroupVersion(client); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("group version", rootTestFunc()) {
		t.Error("test failed")
	}
}

func testGroupVersion(client calicoclient.Interface) error {
	gv := client.ProjectcalicoV3().RESTClient().APIVersion()
	if gv.Group != v3.GroupName {
		return fmt.Errorf("we should be testing the servicecatalog group, not %s", gv.Group)
	}
	return nil
}

func TestEtcdHealthCheckerSuccess(t *testing.T) {
	serverConfig := NewTestServerConfig()
	_, _, clientconfig, shutdownServer := withConfigGetFreshApiserverServerAndClient(t, serverConfig)
	t.Log(clientconfig.Host)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{Transport: tr}
	var success bool
	var resp *http.Response
	var err error
	retryInterval := 500 * time.Millisecond
	for i := 0; i < 5; i++ {
		resp, err = c.Get(clientconfig.Host + "/healthz")
		if nil != err || http.StatusOK != resp.StatusCode {
			success = false
			time.Sleep(retryInterval)
		} else {
			success = true
			break
		}
	}

	if !success {
		t.Fatal("health check endpoint should not have failed")
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("couldn't read response body", err)
	}
	if strings.Contains(string(body), "healthz check failed") {
		t.Fatal("health check endpoint should not have failed")
	}

	defer shutdownServer()
}

// TestNoName checks that all creates fail for objects that have no
// name given.
func TestNoName(t *testing.T) {
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkPolicy{}
			})
			defer shutdownServer()
			if err := testNoName(client); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run("no-name", rootTestFunc()) {
		t.Errorf("NoName test failed")
	}

}

func testNoName(client calicoclient.Interface) error {
	cClient := client.ProjectcalicoV3()

	ns := "default"

	if p, e := cClient.NetworkPolicies(ns).Create(context.Background(), &v3.NetworkPolicy{}, metav1.CreateOptions{}); nil == e {
		return fmt.Errorf("needs a name (%s)", p.Name)
	}

	return nil
}

// TestNetworkPolicyClient exercises the NetworkPolicy client.
func TestNetworkPolicyClient(t *testing.T) {
	const name = "test-networkpolicy"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkPolicy{}
			})
			defer shutdownServer()
			if err := testNetworkPolicyClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-networkpolicy test failed")
	}

}

func testNetworkPolicyClient(client calicoclient.Interface, name string) error {
	ns := "default"
	policyClient := client.ProjectcalicoV3().NetworkPolicies(ns)
	policy := &v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
	ctx := context.Background()

	// start from scratch
	policies, err := policyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing policies (%s)", err)
	}
	if policies.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(policies.Items) > 0 {
		return fmt.Errorf("policies should not exist on start, had %v policies", len(policies.Items))
	}

	policyServer, err := policyClient.Create(ctx, policy, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the policy '%v' (%v)", policy, err)
	}
	if name != policyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}
	if policyServer.ResourceVersion == "" {
		return fmt.Errorf("expected a non-empty resource version. RV=%s", policyServer.ResourceVersion)
	}

	policyServer.Labels = map[string]string{"foo": "bar"}
	policyServer, err = policyClient.Update(ctx, policyServer, metav1.UpdateOptions{})
	if nil != err {
		return fmt.Errorf("error updating the policy '%+v' (%v)", policy, err)
	}
	if name != policyServer.Name {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	policyServer, err = policyClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting policy %s (%s)", name, err)
	}
	if name != policyServer.Name &&
		policy.ResourceVersion == policyServer.ResourceVersion {
		return fmt.Errorf("didn't get the same policy back from the server \n%+v\n%+v", policy, policyServer)
	}

	// Watch Test:
	opts := v1.ListOptions{Watch: true}
	wIface, err := policyClient.Watch(ctx, opts)
	if nil != err {
		return fmt.Errorf("Error on watch")
	}
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		defer wg.Done()
		for e := range wIface.ResultChan() {
			fmt.Println("Watch object: ", e)
			break
		}
	}()

	err = policyClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("policy should be deleted (%s)", err)
	}

	wg.Wait()
	return nil
}

// TestGlobalNetworkPolicyClient exercises the GlobalNetworkPolicy client.
func TestGlobalNetworkPolicyClient(t *testing.T) {
	const name = "test-globalnetworkpolicy"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalNetworkPolicy{}
			})
			defer shutdownServer()
			if err := testGlobalNetworkPolicyClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-globalnetworkpolicy test failed")
	}

}

func testGlobalNetworkPolicyClient(client calicoclient.Interface, name string) error {
	globalNetworkPolicyClient := client.ProjectcalicoV3().GlobalNetworkPolicies()
	globalNetworkPolicy := &v3.GlobalNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
	ctx := context.Background()

	// start from scratch
	globalNetworkPolicies, err := globalNetworkPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkPolicies (%s)", err)
	}
	if globalNetworkPolicies.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	globalNetworkPolicyServer, err := globalNetworkPolicyClient.Create(ctx, globalNetworkPolicy, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the globalNetworkPolicy '%v' (%v)", globalNetworkPolicy, err)
	}
	if name != globalNetworkPolicyServer.Name {
		return fmt.Errorf("didn't get the same globalNetworkPolicy back from the server \n%+v\n%+v", globalNetworkPolicy, globalNetworkPolicyServer)
	}

	globalNetworkPolicies, err = globalNetworkPolicyClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkPolicies (%s)", err)
	}
	if 1 != len(globalNetworkPolicies.Items) {
		return fmt.Errorf("should have exactly one policies, had %v policies", len(globalNetworkPolicies.Items))
	}

	globalNetworkPolicyServer, err = globalNetworkPolicyClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalNetworkPolicy %s (%s)", name, err)
	}
	if name != globalNetworkPolicyServer.Name &&
		globalNetworkPolicy.ResourceVersion == globalNetworkPolicyServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalNetworkPolicy back from the server \n%+v\n%+v", globalNetworkPolicy, globalNetworkPolicyServer)
	}

	err = globalNetworkPolicyClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("globalNetworkPolicy should be deleted (%s)", err)
	}

	return nil
}

// TestGlobalNetworkSetClient exercises the GlobalNetworkSet client.
func TestGlobalNetworkSetClient(t *testing.T) {
	const name = "test-globalnetworkset"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.GlobalNetworkSet{}
			})
			defer shutdownServer()
			if err := testGlobalNetworkSetClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-globalnetworkset test failed")
	}
}

func testGlobalNetworkSetClient(client calicoclient.Interface, name string) error {
	globalNetworkSetClient := client.ProjectcalicoV3().GlobalNetworkSets()
	globalNetworkSet := &v3.GlobalNetworkSet{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	ctx := context.Background()

	// start from scratch
	globalNetworkSets, err := globalNetworkSetClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkSets (%s)", err)
	}
	if globalNetworkSets.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	globalNetworkSetServer, err := globalNetworkSetClient.Create(ctx, globalNetworkSet, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the globalNetworkSet '%v' (%v)", globalNetworkSet, err)
	}
	if name != globalNetworkSetServer.Name {
		return fmt.Errorf("didn't get the same globalNetworkSet back from the server \n%+v\n%+v", globalNetworkSet, globalNetworkSetServer)
	}

	globalNetworkSets, err = globalNetworkSetClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing globalNetworkSets (%s)", err)
	}

	globalNetworkSetServer, err = globalNetworkSetClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting globalNetworkSet %s (%s)", name, err)
	}
	if name != globalNetworkSetServer.Name &&
		globalNetworkSet.ResourceVersion == globalNetworkSetServer.ResourceVersion {
		return fmt.Errorf("didn't get the same globalNetworkSet back from the server \n%+v\n%+v", globalNetworkSet, globalNetworkSetServer)
	}

	err = globalNetworkSetClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("globalNetworkSet should be deleted (%s)", err)
	}

	return nil
}

// TestNetworkSetClient exercises the NetworkSet client.
func TestNetworkSetClient(t *testing.T) {
	const name = "test-networkset"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.NetworkSet{}
			})
			defer shutdownServer()
			if err := testNetworkSetClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-networkset test failed")
	}
}

func testNetworkSetClient(client calicoclient.Interface, name string) error {
	ns := "default"
	networkSetClient := client.ProjectcalicoV3().NetworkSets(ns)
	networkSet := &v3.NetworkSet{ObjectMeta: metav1.ObjectMeta{Name: name}}
	ctx := context.Background()

	// start from scratch
	networkSets, err := networkSetClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing networkSets (%s)", err)
	}
	if networkSets.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}
	if len(networkSets.Items) > 0 {
		return fmt.Errorf("networkSets should not exist on start, had %v networkSets", len(networkSets.Items))
	}

	networkSetServer, err := networkSetClient.Create(ctx, networkSet, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the networkSet '%v' (%v)", networkSet, err)
	}

	updatedNetworkSet := networkSetServer
	updatedNetworkSet.Labels = map[string]string{"foo": "bar"}
	networkSetServer, err = networkSetClient.Update(ctx, updatedNetworkSet, metav1.UpdateOptions{})
	if nil != err {
		return fmt.Errorf("error updating the networkSet '%v' (%v)", networkSet, err)
	}

	// Should be listing the networkSet.
	networkSets, err = networkSetClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing networkSets (%s)", err)
	}
	if 1 != len(networkSets.Items) {
		return fmt.Errorf("should have exactly one networkSet, had %v networkSets", len(networkSets.Items))
	}

	networkSetServer, err = networkSetClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting networkSet %s (%s)", name, err)
	}
	if name != networkSetServer.Name &&
		networkSet.ResourceVersion == networkSetServer.ResourceVersion {
		return fmt.Errorf("didn't get the same networkSet back from the server \n%+v\n%+v", networkSet, networkSetServer)
	}

	// Watch Test:
	opts := v1.ListOptions{Watch: true}
	wIface, err := networkSetClient.Watch(ctx, opts)
	if nil != err {
		return fmt.Errorf("Error on watch")
	}
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		defer wg.Done()
		for e := range wIface.ResultChan() {
			fmt.Println("Watch object: ", e)
			break
		}
	}()

	err = networkSetClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("networkSet should be deleted (%s)", err)
	}

	wg.Wait()
	return nil
}

// TestHostEndpointClient exercises the HostEndpoint client.
func TestHostEndpointClient(t *testing.T) {
	const name = "test-hostendpoint"
	client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
		return &v3.HostEndpoint{}
	})
	defer shutdownServer()
	defer deleteHostEndpointClient(client, name)
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			if err := testHostEndpointClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-hostendpoint test failed")
	}
}

func createTestHostEndpoint(name string, ip string, node string) *v3.HostEndpoint {
	hostEndpoint := &v3.HostEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	hostEndpoint.Spec.ExpectedIPs = []string{ip}
	hostEndpoint.Spec.Node = node

	return hostEndpoint
}

func deleteHostEndpointClient(client calicoclient.Interface, name string) error {
	hostEndpointClient := client.ProjectcalicoV3().HostEndpoints()
	ctx := context.Background()

	return hostEndpointClient.Delete(ctx, name, v1.DeleteOptions{})
}

func testHostEndpointClient(client calicoclient.Interface, name string) error {
	hostEndpointClient := client.ProjectcalicoV3().HostEndpoints()

	hostEndpoint := createTestHostEndpoint(name, "192.168.0.1", "test-node")
	ctx := context.Background()

	// start from scratch
	hostEndpoints, err := hostEndpointClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing hostEndpoints (%s)", err)
	}
	if hostEndpoints.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	hostEndpointServer, err := hostEndpointClient.Create(ctx, hostEndpoint, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the hostEndpoint '%v' (%v)", hostEndpoint, err)
	}
	if name != hostEndpointServer.Name {
		return fmt.Errorf("didn't get the same hostEndpoint back from the server \n%+v\n%+v", hostEndpoint, hostEndpointServer)
	}

	hostEndpoints, err = hostEndpointClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing hostEndpoints (%s)", err)
	}
	if len(hostEndpoints.Items) != 1 {
		return fmt.Errorf("expected 1 hostEndpoint entry, got %d", len(hostEndpoints.Items))
	}

	hostEndpointServer, err = hostEndpointClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting hostEndpoint %s (%s)", name, err)
	}
	if name != hostEndpointServer.Name &&
		hostEndpoint.ResourceVersion == hostEndpointServer.ResourceVersion {
		return fmt.Errorf("didn't get the same hostEndpoint back from the server \n%+v\n%+v", hostEndpoint, hostEndpointServer)
	}

	err = hostEndpointClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("hostEndpoint should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().HostEndpoints().Watch(ctx, v1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching HostEndpoints (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out waiting for events")
				return
			}
		}
		return
	}()

	// Create two HostEndpoints
	for i := 0; i < 2; i++ {
		hep := createTestHostEndpoint(fmt.Sprintf("hep%d", i), "192.168.0.1", "test-node")
		_, err = hostEndpointClient.Create(ctx, hep, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating hostEndpoint '%v' (%v)", hep, err)
		}
	}

	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestIPPoolClient exercises the IPPool client.
func TestIPPoolClient(t *testing.T) {
	const name = "test-ippool"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.IPPool{}
			})
			defer shutdownServer()
			if err := testIPPoolClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-ippool test failed")
	}
}

func testIPPoolClient(client calicoclient.Interface, name string) error {
	ippoolClient := client.ProjectcalicoV3().IPPools()
	ippool := &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.IPPoolSpec{
			CIDR: "192.168.0.0/16",
		},
	}
	ctx := context.Background()

	// start from scratch
	ippools, err := ippoolClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ippools (%s)", err)
	}
	if ippools.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	ippoolServer, err := ippoolClient.Create(ctx, ippool, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the ippool '%v' (%v)", ippool, err)
	}
	if name != ippoolServer.Name {
		return fmt.Errorf("didn't get the same ippool back from the server \n%+v\n%+v", ippool, ippoolServer)
	}

	ippools, err = ippoolClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ippools (%s)", err)
	}

	ippoolServer, err = ippoolClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting ippool %s (%s)", name, err)
	}
	if name != ippoolServer.Name &&
		ippool.ResourceVersion == ippoolServer.ResourceVersion {
		return fmt.Errorf("didn't get the same ippool back from the server \n%+v\n%+v", ippool, ippoolServer)
	}

	err = ippoolClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("ippool should be deleted (%s)", err)
	}

	return nil
}

// TestIPReservationClient exercises the IPReservation client.
func TestIPReservationClient(t *testing.T) {
	const name = "test-ipreservation"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.IPReservation{}
			})
			defer shutdownServer()
			if err := testIPReservationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-ipreservation test failed")
	}
}

func testIPReservationClient(client calicoclient.Interface, name string) error {
	ipreservationClient := client.ProjectcalicoV3().IPReservations()
	ipreservation := &v3.IPReservation{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.IPReservationSpec{
			ReservedCIDRs: []string{"192.168.0.0/16"},
		},
	}
	ctx := context.Background()

	// start from scratch
	ipreservations, err := ipreservationClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ipreservations (%s)", err)
	}
	if ipreservations.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	ipreservationServer, err := ipreservationClient.Create(ctx, ipreservation, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the ipreservation '%v' (%v)", ipreservation, err)
	}
	if name != ipreservationServer.Name {
		return fmt.Errorf("didn't get the same ipreservation back from the server \n%+v\n%+v", ipreservation, ipreservationServer)
	}

	ipreservations, err = ipreservationClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ipreservations (%s)", err)
	}

	ipreservationServer, err = ipreservationClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting ipreservation %s (%s)", name, err)
	}
	if name != ipreservationServer.Name &&
		ipreservation.ResourceVersion == ipreservationServer.ResourceVersion {
		return fmt.Errorf("didn't get the same ipreservation back from the server \n%+v\n%+v", ipreservation, ipreservationServer)
	}

	err = ipreservationClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("ipreservation should be deleted (%s)", err)
	}

	return nil
}

// TestBGPConfigurationClient exercises the BGPConfiguration client.
func TestBGPConfigurationClient(t *testing.T) {
	const name = "test-bgpconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.BGPConfiguration{}
			})
			defer shutdownServer()
			if err := testBGPConfigurationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-bgpconfig test failed")
	}
}

func testBGPConfigurationClient(client calicoclient.Interface, name string) error {
	bgpConfigClient := client.ProjectcalicoV3().BGPConfigurations()
	resName := "bgpconfig-test"
	bgpConfig := &v3.BGPConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: resName},
		Spec: v3.BGPConfigurationSpec{
			LogSeverityScreen: "Info",
		},
	}
	ctx := context.Background()

	// start from scratch
	bgpConfigList, err := bgpConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing bgpConfiguration (%s)", err)
	}
	if bgpConfigList.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	bgpRes, err := bgpConfigClient.Create(ctx, bgpConfig, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the bgpConfiguration '%v' (%v)", bgpConfig, err)
	}
	if resName != bgpRes.Name {
		return fmt.Errorf("didn't get the same bgpConfig back from server\n%+v\n%+v", bgpConfig, bgpRes)
	}

	bgpRes, err = bgpConfigClient.Get(ctx, resName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting bgpConfiguration %s (%s)", resName, err)
	}

	err = bgpConfigClient.Delete(ctx, resName, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("BGPConfiguration should be deleted (%s)", err)
	}

	return nil
}

// TestBGPPeerClient exercises the BGPPeer client.
func TestBGPPeerClient(t *testing.T) {
	const name = "test-bgppeer"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.BGPPeer{}
			})
			defer shutdownServer()
			if err := testBGPPeerClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-bgppeer test failed")
	}
}

func testBGPPeerClient(client calicoclient.Interface, name string) error {
	bgpPeerClient := client.ProjectcalicoV3().BGPPeers()
	resName := "bgppeer-test"
	bgpPeer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: resName},
		Spec: v3.BGPPeerSpec{
			Node:     "node1",
			PeerIP:   "10.0.0.1",
			ASNumber: numorstring.ASNumber(6512),
		},
	}
	ctx := context.Background()

	// start from scratch
	bgpPeerList, err := bgpPeerClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing bgpPeer (%s)", err)
	}
	if bgpPeerList.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	bgpRes, err := bgpPeerClient.Create(ctx, bgpPeer, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the bgpPeer '%v' (%v)", bgpPeer, err)
	}
	if resName != bgpRes.Name {
		return fmt.Errorf("didn't get the same bgpPeer back from server\n%+v\n%+v", bgpPeer, bgpRes)
	}

	bgpRes, err = bgpPeerClient.Get(ctx, resName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting bgpPeer %s (%s)", resName, err)
	}

	err = bgpPeerClient.Delete(ctx, resName, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("BGPPeer should be deleted (%s)", err)
	}

	return nil
}

// TestProfileClient exercises the Profile client.
func TestProfileClient(t *testing.T) {
	// This matches the namespace that is created at test setup time in the Makefile.
	// TODO(doublek): Note that this currently only works for KDD mode.
	const name = "kns.namespace-1"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.Profile{}
			})
			defer shutdownServer()
			if err := testProfileClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-profile test failed")
	}
}

func testProfileClient(client calicoclient.Interface, name string) error {
	profileClient := client.ProjectcalicoV3().Profiles()
	profile := &v3.Profile{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.ProfileSpec{
			LabelsToApply: map[string]string{
				"aa": "bb",
			},
		},
	}
	ctx := context.Background()

	// start from scratch
	profileList, err := profileClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing profile (%s)", err)
	}
	if profileList.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	// Profile creation is not supported.
	_, err = profileClient.Create(ctx, profile, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("profile should not be allowed to be created'%v' (%v)", profile, err)
	}

	profileRes, err := profileClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting profile %s (%s)", name, err)
	}

	if name != profileRes.Name {
		return fmt.Errorf("didn't get the same profile back from server\n%+v\n%+v", profile, profileRes)
	}

	// Profile deletion is not supported.
	err = profileClient.Delete(ctx, name, metav1.DeleteOptions{})
	if err == nil {
		return fmt.Errorf("Profile cannot be deleted (%s)", err)
	}

	return nil
}

// TestFelixConfigurationClient exercises the FelixConfiguration client.
func TestFelixConfigurationClient(t *testing.T) {
	const name = "test-felixconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.FelixConfiguration{}
			})
			defer shutdownServer()
			if err := testFelixConfigurationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-felixConfig test failed")
	}
}

func testFelixConfigurationClient(client calicoclient.Interface, name string) error {
	felixConfigClient := client.ProjectcalicoV3().FelixConfigurations()
	ptrTrue := true
	ptrInt := 1432
	felixConfig := &v3.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.FelixConfigurationSpec{
			UseInternalDataplaneDriver: &ptrTrue,
			DataplaneDriver:            "test-dataplane-driver",
			MetadataPort:               &ptrInt,
		},
	}
	ctx := context.Background()

	// start from scratch
	felixConfigs, err := felixConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing felixConfigs (%s)", err)
	}
	if felixConfigs.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	felixConfigServer, err := felixConfigClient.Create(ctx, felixConfig, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the felixConfig '%v' (%v)", felixConfig, err)
	}
	if name != felixConfigServer.Name {
		return fmt.Errorf("didn't get the same felixConfig back from the server \n%+v\n%+v", felixConfig, felixConfigServer)
	}

	felixConfigs, err = felixConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing felixConfigs (%s)", err)
	}

	felixConfigServer, err = felixConfigClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting felixConfig %s (%s)", name, err)
	}
	if name != felixConfigServer.Name &&
		felixConfig.ResourceVersion == felixConfigServer.ResourceVersion {
		return fmt.Errorf("didn't get the same felixConfig back from the server \n%+v\n%+v", felixConfig, felixConfigServer)
	}

	err = felixConfigClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("felixConfig should be deleted (%s)", err)
	}

	return nil
}

// TestKubeControllersConfigurationClient exercises the KubeControllersConfiguration client.
func TestKubeControllersConfigurationClient(t *testing.T) {
	const name = "test-kubecontrollersconfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.KubeControllersConfiguration{}
			})
			defer shutdownServer()
			if err := testKubeControllersConfigurationClient(client); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-kubecontrollersconfig test failed")
	}
}

func testKubeControllersConfigurationClient(client calicoclient.Interface) error {
	kubeControllersConfigClient := client.ProjectcalicoV3().KubeControllersConfigurations()
	kubeControllersConfig := &v3.KubeControllersConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Status: v3.KubeControllersConfigurationStatus{
			RunningConfig: v3.KubeControllersConfigurationSpec{
				Controllers: v3.ControllersConfig{
					Node: &v3.NodeControllerConfig{
						SyncLabels: v3.Enabled,
					},
				},
			},
		},
	}
	ctx := context.Background()

	// start from scratch
	kubeControllersConfigs, err := kubeControllersConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing kubeControllersConfigs (%s)", err)
	}
	if kubeControllersConfigs.Items == nil {
		return fmt.Errorf("Items field should not be set to nil")
	}

	kubeControllersConfigServer, err := kubeControllersConfigClient.Create(ctx, kubeControllersConfig, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the kubeControllersConfig '%v' (%v)", kubeControllersConfig, err)
	}
	if kubeControllersConfigServer.Name != "default" {
		return fmt.Errorf("didn't get the same kubeControllersConfig back from the server \n%+v\n%+v", kubeControllersConfig, kubeControllersConfigServer)
	}
	if !reflect.DeepEqual(kubeControllersConfigServer.Status, v3.KubeControllersConfigurationStatus{}) {
		return fmt.Errorf("status was set on create to %#v", kubeControllersConfigServer.Status)
	}

	kubeControllersConfigs, err = kubeControllersConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing kubeControllersConfigs (%s)", err)
	}
	if len(kubeControllersConfigs.Items) != 1 {
		return fmt.Errorf("expected 1 kubeControllersConfig got %d", len(kubeControllersConfigs.Items))
	}

	kubeControllersConfigServer, err = kubeControllersConfigClient.Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting kubeControllersConfig default (%s)", err)
	}
	if kubeControllersConfigServer.Name != "default" &&
		kubeControllersConfig.ResourceVersion == kubeControllersConfigServer.ResourceVersion {
		return fmt.Errorf("didn't get the same kubeControllersConfig back from the server \n%+v\n%+v", kubeControllersConfig, kubeControllersConfigServer)
	}

	kubeControllersConfigUpdate := kubeControllersConfigServer.DeepCopy()
	kubeControllersConfigUpdate.Spec.HealthChecks = v3.Enabled
	kubeControllersConfigUpdate.Status.EnvironmentVars = map[string]string{"FOO": "bar"}
	kubeControllersConfigServer, err = kubeControllersConfigClient.Update(ctx, kubeControllersConfigUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating kubeControllersConfig default (%s)", err)
	}
	if kubeControllersConfigServer.Spec.HealthChecks != kubeControllersConfigUpdate.Spec.HealthChecks {
		return errors.New("didn't update spec.content")
	}
	if kubeControllersConfigServer.Status.EnvironmentVars != nil {
		return errors.New("status was updated by Update()")
	}

	kubeControllersConfigUpdate = kubeControllersConfigServer.DeepCopy()
	kubeControllersConfigUpdate.Status.EnvironmentVars = map[string]string{"FIZZ": "buzz"}
	kubeControllersConfigUpdate.Labels = map[string]string{"foo": "bar"}
	kubeControllersConfigUpdate.Spec.HealthChecks = ""
	kubeControllersConfigServer, err = kubeControllersConfigClient.UpdateStatus(ctx, kubeControllersConfigUpdate, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating kubeControllersConfig default (%s)", err)
	}
	if !reflect.DeepEqual(kubeControllersConfigServer.Status, kubeControllersConfigUpdate.Status) {
		return fmt.Errorf("didn't update status. %v != %v", kubeControllersConfigUpdate.Status, kubeControllersConfigServer.Status)
	}
	if _, ok := kubeControllersConfigServer.Labels["foo"]; ok {
		return fmt.Errorf("updatestatus updated labels")
	}
	if kubeControllersConfigServer.Spec.HealthChecks == "" {
		return fmt.Errorf("updatestatus updated spec")
	}

	err = kubeControllersConfigClient.Delete(ctx, "default", metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("kubeControllersConfig should be deleted (%s)", err)
	}

	// Test watch
	w, err := client.ProjectcalicoV3().KubeControllersConfigurations().Watch(ctx, v1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching KubeControllersConfigurations (%s)", err)
	}
	var events []watch.Event
	done := sync.WaitGroup{}
	done.Add(1)
	timeout := time.After(500 * time.Millisecond)
	var timeoutErr error
	// watch for 2 events
	go func() {
		defer done.Done()
		for i := 0; i < 2; i++ {
			select {
			case e := <-w.ResultChan():
				events = append(events, e)
			case <-timeout:
				timeoutErr = fmt.Errorf("timed out waiting for events")
				return
			}
		}
		return
	}()

	// Create, then delete KubeControllersConfigurations
	kubeControllersConfigServer, err = kubeControllersConfigClient.Create(ctx, kubeControllersConfig, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the kubeControllersConfig '%v' (%v)", kubeControllersConfig, err)
	}
	err = kubeControllersConfigClient.Delete(ctx, "default", metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("kubeControllersConfig should be deleted (%s)", err)
	}

	done.Wait()
	if timeoutErr != nil {
		return timeoutErr
	}
	if len(events) != 2 {
		return fmt.Errorf("expected 2 watch events got %d", len(events))
	}

	return nil
}

// TestClusterInformationClient exercises the ClusterInformation client.
func TestClusterInformationClient(t *testing.T) {
	const name = "default"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.ClusterInformation{}
			})
			defer shutdownServer()
			if err := testClusterInformationClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-clusterinformation test failed")
	}
}

func testClusterInformationClient(client calicoclient.Interface, name string) error {
	clusterInformationClient := client.ProjectcalicoV3().ClusterInformations()
	ctx := context.Background()

	ci, err := clusterInformationClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ClusterInformation (%s)", err)
	}
	if ci.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	// Confirm it's not possible to edit the default cluster information.
	info := ci.Items[0]
	info.Spec.CalicoVersion = "fakeVersion"
	_, err = clusterInformationClient.Update(ctx, &info, metav1.UpdateOptions{})
	if err == nil {
		return fmt.Errorf("expected error updating default clusterinformation")
	}

	// Should also not be able to delete it.
	err = clusterInformationClient.Delete(ctx, "default", metav1.DeleteOptions{})
	if err == nil {
		return fmt.Errorf("expected error updating default clusterinformation")
	}

	// Confirm it's not possible to create a clusterInformation obj with name other than "default"
	invalidClusterInfo := &v3.ClusterInformation{ObjectMeta: metav1.ObjectMeta{Name: "test-clusterinformation"}}
	_, err = clusterInformationClient.Create(ctx, invalidClusterInfo, metav1.CreateOptions{})
	if err == nil {
		return fmt.Errorf("expected error creating invalidClusterInfo with name other than \"default\"")
	}

	return nil
}

// TestCalicoNodeStatusClient exercises the CalicoNodeStatus client.
func TestCalicoNodeStatusClient(t *testing.T) {
	const name = "test-caliconodestatus"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.CalicoNodeStatus{}
			})
			defer shutdownServer()
			if err := testCalicoNodeStatusClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-caliconodestatus test failed")
	}
}

func testCalicoNodeStatusClient(client calicoclient.Interface, name string) error {
	seconds := uint32(11)
	caliconodestatusClient := client.ProjectcalicoV3().CalicoNodeStatuses()
	caliconodestatus := &v3.CalicoNodeStatus{
		ObjectMeta: metav1.ObjectMeta{Name: name},

		Spec: v3.CalicoNodeStatusSpec{
			Node: "node1",
			Classes: []v3.NodeStatusClassType{
				v3.NodeStatusClassTypeAgent,
				v3.NodeStatusClassTypeBGP,
				v3.NodeStatusClassTypeRoutes,
			},
			UpdatePeriodSeconds: &seconds,
		},
	}
	ctx := context.Background()

	// start from scratch
	caliconodestatuses, err := caliconodestatusClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing caliconodestatuses (%s)", err)
	}
	if caliconodestatuses.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	caliconodestatusNew, err := caliconodestatusClient.Create(ctx, caliconodestatus, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the object '%v' (%v)", caliconodestatus, err)
	}
	if name != caliconodestatusNew.Name {
		return fmt.Errorf("didn't get the same object back from the server \n%+v\n%+v", caliconodestatus, caliconodestatusNew)
	}

	caliconodestatusNew, err = caliconodestatusClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", name, err)
	}

	err = caliconodestatusClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("object should be deleted (%s)", err)
	}

	return nil
}

// TestIPAMConfigClient exercises the IPAMConfig client.
func TestIPAMConfigClient(t *testing.T) {
	const name = "test-IPAMConfig"
	rootTestFunc := func() func(t *testing.T) {
		return func(t *testing.T) {
			client, shutdownServer := getFreshApiserverAndClient(t, func() runtime.Object {
				return &v3.IPAMConfig{}
			})
			defer shutdownServer()
			if err := testIPAMConfigClient(client, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !t.Run(name, rootTestFunc()) {
		t.Errorf("test-IPAMConfig test failed")
	}
}

func testIPAMConfigClient(client calicoclient.Interface, name string) error {
	ipamConfigClient := client.ProjectcalicoV3().IPAMConfigs()
	ipamConfig := &v3.IPAMConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},

		Spec: v3.IPAMConfigSpec{
			StrictAffinity:   true,
			MaxBlocksPerHost: 2,
		},
	}
	ctx := context.Background()

	// start from scratch
	ipamConfigs, err := ipamConfigClient.List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing ipamConfigs (%s)", err)
	}
	if ipamConfigs.Items == nil {
		return fmt.Errorf("items field should not be set to nil")
	}

	ipamConfigNew, err := ipamConfigClient.Create(ctx, ipamConfig, metav1.CreateOptions{})
	if nil != err {
		return fmt.Errorf("error creating the object '%v' (%v)", ipamconfig, err)
	}
	if name != ipamConfigNew.Name {
		return fmt.Errorf("didn't get the same object back from the server \n%+v\n%+v", ipamConfig, ipamConfigNew)
	}

	ipamConfigNew, err = ipamConfigClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting object %s (%s)", name, err)
	}

	err = ipamConfigClient.Delete(ctx, name, metav1.DeleteOptions{})
	if nil != err {
		return fmt.Errorf("object should be deleted (%s)", err)
	}

	return nil
}
