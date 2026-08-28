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

package applicationlayer_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/tigera/operator/pkg/render/applicationlayer"
)

var fakeCABundle = []byte("fake-ca-bundle")

// The webhook runs in-process in calico-kube-controllers, so the render emits
// only a Service fronting the kube-controllers Pod plus the
// ValidatingWebhookConfiguration — no Deployment/ServiceAccount/ClusterRole.
func TestWAFAdmissionWebhookComponents_HasExpectedKinds(t *testing.T) {
	objs := applicationlayer.WAFAdmissionWebhookComponents(fakeCABundle)
	got := map[string]int{}
	for _, o := range objs {
		got[o.GetObjectKind().GroupVersionKind().Kind]++
	}
	require.Len(t, objs, 2, "expected exactly 2 objects (Service + ValidatingWebhookConfiguration)")
	require.Equal(t, 1, got["Service"], "expected 1 Service")
	require.Equal(t, 1, got["ValidatingWebhookConfiguration"], "expected 1 ValidatingWebhookConfiguration")
	require.Zero(t, got["Deployment"], "in-process webhook must not render a Deployment")
	require.Zero(t, got["ServiceAccount"], "in-process webhook reuses the kube-controllers ServiceAccount")
	require.Zero(t, got["ClusterRole"], "in-process webhook reuses the kube-controllers ClusterRole")
}

// The Service must front the calico-kube-controllers Pod and forward to the
// in-process webhook port (9443).
func TestWAFAdmissionWebhookComponents_ServiceFrontsKubeControllers(t *testing.T) {
	objs := applicationlayer.WAFAdmissionWebhookComponents(fakeCABundle)
	var svc *corev1.Service
	for _, o := range objs {
		if s, ok := o.(*corev1.Service); ok {
			svc = s
		}
	}
	require.NotNil(t, svc, "expected a Service")
	require.Equal(t, "calico-kube-controllers", svc.Spec.Selector["k8s-app"], "Service must select the kube-controllers Pod")
	require.Len(t, svc.Spec.Ports, 1)
	require.Equal(t, int32(443), svc.Spec.Ports[0].Port)
	require.Equal(t, int32(9443), svc.Spec.Ports[0].TargetPort.IntVal, "must forward to the in-process webhook port")
}

// The webhook must intercept WAFPlugin/WAFPolicy on the /validate-waf path,
// carry the supplied CA bundle, and fail closed.
func TestWAFAdmissionWebhookComponents_WebhookContract(t *testing.T) {
	objs := applicationlayer.WAFAdmissionWebhookComponents(fakeCABundle)
	var vwc *admissionregistrationv1.ValidatingWebhookConfiguration
	for _, o := range objs {
		if w, ok := o.(*admissionregistrationv1.ValidatingWebhookConfiguration); ok {
			vwc = w
		}
	}
	require.NotNil(t, vwc, "expected a ValidatingWebhookConfiguration")
	require.Len(t, vwc.Webhooks, 1)
	wh := vwc.Webhooks[0]

	require.Len(t, wh.Rules, 1)
	require.ElementsMatch(t, []string{"wafplugins", "wafpolicies"}, wh.Rules[0].Resources)
	require.Equal(t, []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create, admissionregistrationv1.Update,
	}, wh.Rules[0].Operations)

	require.NotNil(t, wh.ClientConfig.Service)
	require.Equal(t, "tigera-waf-webhook", wh.ClientConfig.Service.Name)
	require.Equal(t, "/validate-waf", *wh.ClientConfig.Service.Path)
	require.Equal(t, fakeCABundle, wh.ClientConfig.CABundle, "caBundle must be the supplied issuing-CA PEM")

	require.NotNil(t, wh.FailurePolicy)
	require.Equal(t, admissionregistrationv1.Fail, *wh.FailurePolicy, "webhook must fail closed")
}
