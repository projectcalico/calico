// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package migration

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/operator/pkg/common"
)

func TestDeleteKubeSystemWebhooksRemovesTheManifestServer(t *testing.T) {
	g := NewWithT(t)

	m := &CoreNamespaceMigration{client: fake.NewClientset(
		kubeSystemWebhooks(),
		kubeSystemWebhooksService(),
		kubeSystemWebhooksConfiguration(),
		operatorWebhooks(1),
	)}

	g.Expect(m.deleteKubeSystemWebhooks(context.Background(), logr.Discard())).To(Succeed())

	_, err := m.client.AppsV1().Deployments(kubeSystem).Get(context.Background(), webhooksDeploymentName, metav1.GetOptions{})
	g.Expect(apierrs.IsNotFound(err)).To(BeTrue(), "the kube-system deployment should be gone")
	_, err = m.client.CoreV1().Services(kubeSystem).Get(context.Background(), webhooksDeploymentName, metav1.GetOptions{})
	g.Expect(apierrs.IsNotFound(err)).To(BeTrue(), "the kube-system service should be gone")
	_, err = m.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), webhooksDeploymentName, metav1.GetOptions{})
	g.Expect(apierrs.IsNotFound(err)).To(BeTrue(), "the configuration pointing at it should be gone")
}

// Deleting the only server behind a webhook that fails closed would reject every
// policy write, so a cluster without the operator's own server keeps this one.
func TestDeleteKubeSystemWebhooksKeepsTheOnlyServer(t *testing.T) {
	g := NewWithT(t)

	m := &CoreNamespaceMigration{client: fake.NewClientset(
		kubeSystemWebhooks(),
		kubeSystemWebhooksService(),
		kubeSystemWebhooksConfiguration(),
		operatorWebhooks(0),
	)}

	// The deadline stands in for the wait this would otherwise sit through.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	g.Expect(m.deleteKubeSystemWebhooks(ctx, logr.Discard())).To(Succeed())

	_, err := m.client.AppsV1().Deployments(kubeSystem).Get(context.Background(), webhooksDeploymentName, metav1.GetOptions{})
	g.Expect(err).ToNot(HaveOccurred(), "the kube-system deployment should still be there")
	_, err = m.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), webhooksDeploymentName, metav1.GetOptions{})
	g.Expect(err).ToNot(HaveOccurred(), "the configuration should still be there")
}

func kubeSystemWebhooks() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webhooksDeploymentName,
			Namespace: kubeSystem,
		},
	}
}

func kubeSystemWebhooksService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webhooksDeploymentName,
			Namespace: kubeSystem,
		},
	}
}

func kubeSystemWebhooksConfiguration() *admissionregistrationv1.ValidatingWebhookConfiguration {
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: webhooksDeploymentName},
	}
}

func operatorWebhooks(available int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webhooksDeploymentName,
			Namespace: common.CalicoNamespace,
		},
		Status: appsv1.DeploymentStatus{AvailableReplicas: available},
	}
}
