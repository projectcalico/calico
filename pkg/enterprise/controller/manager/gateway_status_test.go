// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package manager

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/tigera/operator/pkg/apis"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("gatewayUnhealthyReason", func() {
	const ns = "calico-system"

	var (
		ctx context.Context
		r   *ReconcileManager
	)

	cond := func(t string, status metav1.ConditionStatus, msg string) metav1.Condition {
		return metav1.Condition{Type: t, Status: status, Message: msg, Reason: "Test", LastTransitionTime: metav1.Now()}
	}

	newGateway := func(conds ...metav1.Condition) *gapi.Gateway {
		return &gapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: ManagerGatewayResourcePrefix + "-gateway", Namespace: ns},
			Status:     gapi.GatewayStatus{Conditions: conds},
		}
	}

	newRoute := func(conds ...metav1.Condition) *gapi.HTTPRoute {
		route := &gapi.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: ManagerGatewayResourcePrefix + "-route", Namespace: ns},
		}
		if len(conds) > 0 {
			route.Status.Parents = []gapi.RouteParentStatus{{Conditions: conds}}
		}
		return route
	}

	healthyGateway := func() *gapi.Gateway {
		return newGateway(
			cond(string(gapi.GatewayConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.GatewayConditionProgrammed), metav1.ConditionTrue, ""),
		)
	}

	build := func(objs ...client.Object) {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(objs...).Build()
		r = &ReconcileManager{client: cli}
	}

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("reports a missing Gateway", func() {
		build()
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(ContainSubstring("not found yet"))
	})

	It("reports Gateway not accepted", func() {
		build(newGateway(cond(string(gapi.GatewayConditionAccepted), metav1.ConditionFalse, "invalid listener")))
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(Equal("Gateway not accepted: invalid listener"))
	})

	It("reports Gateway not programmed", func() {
		build(newGateway(
			cond(string(gapi.GatewayConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.GatewayConditionProgrammed), metav1.ConditionFalse, "no addresses assigned"),
		))
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(Equal("Gateway not programmed: no addresses assigned"))
	})

	It("treats missing Gateway conditions as healthy and moves on to the HTTPRoute", func() {
		build(newGateway(), newRoute())
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(BeEmpty())
	})

	It("reports a missing HTTPRoute once the Gateway is healthy", func() {
		build(healthyGateway())
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(ContainSubstring("HTTPRoute"))
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(ContainSubstring("not found yet"))
	})

	It("reports HTTPRoute not accepted", func() {
		build(healthyGateway(), newRoute(cond(string(gapi.RouteConditionAccepted), metav1.ConditionFalse, "no matching parent")))
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(Equal("HTTPRoute not accepted: no matching parent"))
	})

	It("reports HTTPRoute refs not resolved", func() {
		build(healthyGateway(), newRoute(
			cond(string(gapi.RouteConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.RouteConditionResolvedRefs), metav1.ConditionFalse, "backend not permitted"),
		))
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(Equal("HTTPRoute refs not resolved: backend not permitted"))
	})

	It("returns empty when the Gateway and HTTPRoute are healthy", func() {
		build(healthyGateway(), newRoute(
			cond(string(gapi.RouteConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.RouteConditionResolvedRefs), metav1.ConditionTrue, ""),
		))
		Expect(r.gatewayUnhealthyReason(ctx, ns)).To(BeEmpty())
	})
})

var _ = DescribeTable("managerDomainHost",
	func(input, expected string) {
		Expect(managerDomainHost(input)).To(Equal(expected))
	},
	Entry("bare host", "manager.example.com", "manager.example.com"),
	Entry("https scheme", "https://manager.example.com", "manager.example.com"),
	Entry("http scheme", "http://manager.example.com", "manager.example.com"),
	Entry("explicit default port", "https://manager.example.com:443", "manager.example.com"),
	Entry("non-default port", "manager.example.com:9443", "manager.example.com"),
	Entry("scheme and port", "https://manager.example.com:9443", "manager.example.com"),
	Entry("bare IPv6 without port", "2001:db8::1", "2001:db8::1"),
	Entry("bracketed IPv6 with port", "[2001:db8::1]:443", "2001:db8::1"),
)
