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

package utils

import (
	"context"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NginxImage is the web-server image deployed behind the test services. Overridable via $NGINX_IMAGE .
var NginxImage = envOr("NGINX_IMAGE", "nginx:1")

// DeployOptions create_service. The zero value reproduces a single replica, a NodePort service with externalTrafficPolicy=Local.
type DeployOptions struct {
	// Replicas defaults to 1 when zero.
	Replicas int32
	// SvcType defaults to NodePort when empty.
	SvcType corev1.ServiceType
	// TrafficPolicy defaults to Local when empty.
	TrafficPolicy corev1.ServiceExternalTrafficPolicy
	// ClusterIP, when set, pins the service's clusterIP.
	ClusterIP string
	// ExtIP, when set, is added to the service's externalIPs.
	ExtIP string
	// IPv6, when true, requests an IPv6 single-stack service.
	IPv6 bool
}

func (o DeployOptions) replicas() int32 {
	if o.Replicas == 0 {
		return 1
	}
	return o.Replicas
}

func (o DeployOptions) svcType() corev1.ServiceType {
	if o.SvcType == "" {
		return corev1.ServiceTypeNodePort
	}
	return o.SvcType
}

func (o DeployOptions) trafficPolicy() corev1.ServiceExternalTrafficPolicy {
	if o.TrafficPolicy == "" {
		return corev1.ServiceExternalTrafficPolicyLocal
	}
	return o.TrafficPolicy
}

// CreateNamespace creates a namespace, fatally failing the test on error.
// Mirrors test_base.py:create_namespace.
func CreateNamespace(t testing.TB, name string) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	_, err := K8sClient(t).CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating namespace %s: %v", name, err)
	}
}

// Deploy creates a Deployment (with pod anti-affinity so replicas prefer
// distinct nodes) and a matching Service.
func Deploy(t testing.TB, image, name, ns string, port int32, opts DeployOptions) {
	t.Helper()

	labels := map[string]string{"app": name}
	selector := &metav1.LabelSelector{MatchLabels: labels}

	// Prefer scheduling replicas on different nodes — several tests assert
	// ECMP routing, which requires pods spread across nodes.
	antiAffinity := &corev1.PodAntiAffinity{
		PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
			Weight: 100,
			PodAffinityTerm: corev1.PodAffinityTerm{
				LabelSelector: selector,
				TopologyKey:   "kubernetes.io/hostname",
			},
		}},
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(opts.replicas()),
			Selector: selector,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{PodAntiAffinity: antiAffinity},
					Containers: []corev1.Container{{
						Name:  name,
						Image: image,
						Ports: []corev1.ContainerPort{{ContainerPort: port}},
					}},
				},
			},
		},
	}
	_, err := K8sClient(t).AppsV1().Deployments(ns).Create(context.Background(), deployment, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating deployment %s/%s: %v", ns, name, err)
	}

	// Create the service selecting this deployment's pods.
	CreateService(t, name, name, ns, port, opts)
}

// CreateService creates a Service named `name` selecting pods labelled
// app=`app`. Mirrors test_base.py:create_service.
func CreateService(t testing.TB, name, app, ns string, port int32, opts DeployOptions) {
	t.Helper()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"name": name},
		},
		Spec: corev1.ServiceSpec{
			Ports:                 []corev1.ServicePort{{Port: port}},
			Selector:              map[string]string{"app": app},
			Type:                  opts.svcType(),
			ExternalTrafficPolicy: opts.trafficPolicy(),
		},
	}
	if opts.svcType() == corev1.ServiceTypeLoadBalancer {
		// Pin LB IPAM to Calico's loadbalancer controller. Without this,
		// metallb's ServiceReconciler (still installed for Gateway API
		// conformance) races Calico's status updates and leaves
		// status.loadBalancer empty.
		svc.Spec.LoadBalancerClass = new("calico")
	}
	if opts.ClusterIP != "" {
		svc.Spec.ClusterIP = opts.ClusterIP
	}
	if opts.ExtIP != "" {
		svc.Spec.ExternalIPs = []string{opts.ExtIP}
	}
	if opts.IPv6 {
		svc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv6Protocol}
	}

	_, err := K8sClient(t).CoreV1().Services(ns).Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating service %s/%s: %v", ns, name, err)
	}
}

// WaitForDeployment blocks until the deployment has fully rolled out (its
// updated/available replica counts match the desired count for the latest
// generation), fatally failing on timeout. The client-go equivalent of
// `kubectl rollout status deployment/<name>`.
func WaitForDeployment(t testing.TB, name, ns string) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 2*time.Minute, func() error {
		d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		if d.Status.ObservedGeneration < d.Generation {
			return fmt.Errorf("deployment %s/%s not yet observed (gen %d < %d)",
				ns, name, d.Status.ObservedGeneration, d.Generation)
		}
		if d.Status.UpdatedReplicas != desired ||
			d.Status.Replicas != desired ||
			d.Status.AvailableReplicas != desired {
			return fmt.Errorf("deployment %s/%s not rolled out: updated=%d replicas=%d available=%d desired=%d",
				ns, name, d.Status.UpdatedReplicas, d.Status.Replicas, d.Status.AvailableReplicas, desired)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("deployment %s/%s did not roll out: %v", ns, name, err)
	}
}

// ScaleDeployment sets the deployment's replica count.
func ScaleDeployment(t testing.TB, name, ns string, replicas int32) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 30*time.Second, func() error {
		d, err := cs.AppsV1().Deployments(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		d.Spec.Replicas = new(replicas)
		_, err = cs.AppsV1().Deployments(ns).Update(context.Background(), d, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("scaling deployment %s/%s to %d: %v", ns, name, replicas, err)
	}
}

// WaitUntilExists blocks until the named resource exists, fatally failing on
// timeout. Only "svc" is supported.
func WaitUntilExists(t testing.TB, name, resourceType, ns string) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 90*time.Second, func() error {
		switch resourceType {
		case "svc":
			_, err := cs.CoreV1().Services(ns).Get(context.Background(), name, metav1.GetOptions{})
			return err
		default:
			t.Fatalf("WaitUntilExists: unsupported resource type %q", resourceType)
			return nil
		}
	})
	if err != nil {
		t.Fatalf("%s %s/%s never appeared: %v", resourceType, ns, name, err)
	}
}

// DeleteAndConfirm deletes the named resource and blocks until it is gone from
// the API, fatally failing on timeout. Supports "svc" and "ns".
func DeleteAndConfirm(t testing.TB, name, resourceType, ns string) {
	t.Helper()
	cs := K8sClient(t)

	del := func() error {
		switch resourceType {
		case "svc":
			return cs.CoreV1().Services(ns).Delete(context.Background(), name, metav1.DeleteOptions{})
		case "ns":
			return cs.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
		default:
			t.Fatalf("DeleteAndConfirm: unsupported resource type %q", resourceType)
			return nil
		}
	}
	if err := del(); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("deleting %s %s/%s: %v", resourceType, ns, name, err)
	}

	gone := func() error {
		var err error
		switch resourceType {
		case "svc":
			_, err = cs.CoreV1().Services(ns).Get(context.Background(), name, metav1.GetOptions{})
		case "ns":
			_, err = cs.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
		}
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("%s %s/%s still exists", resourceType, ns, name)
	}
	if err := RetryUntilSuccess(t, 120*time.Second, gone); err != nil {
		t.Fatalf("%s %s/%s was not deleted: %v", resourceType, ns, name, err)
	}
}

func GetSvcClusterIP(t testing.TB, svc, ns string) string {
	t.Helper()
	s, err := K8sClient(t).CoreV1().Services(ns).Get(context.Background(), svc, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting service %s/%s: %v", ns, svc, err)
	}
	return s.Spec.ClusterIP
}

// GetSvcLoadBalancerIP returns the allocated LoadBalancer ingress IP, retrying for up to 10s.
func GetSvcLoadBalancerIP(t testing.TB, svc, ns string) string {
	t.Helper()
	cs := K8sClient(t)
	var lbIP string
	err := RetryUntilSuccess(t, 10*time.Second, func() error {
		s, err := cs.CoreV1().Services(ns).Get(context.Background(), svc, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if len(s.Status.LoadBalancer.Ingress) == 0 || s.Status.LoadBalancer.Ingress[0].IP == "" {
			return fmt.Errorf("no LoadBalancer IP found for service %s/%s", ns, svc)
		}
		lbIP = s.Status.LoadBalancer.Ingress[0].IP
		return nil
	})
	if err != nil {
		t.Fatalf("waiting for LoadBalancer IP on %s/%s: %v", ns, svc, err)
	}
	return lbIP
}

// GetSvcHostIP returns the hostIP of the first pod backing the service (matched
// by label app=<app>).
func GetSvcHostIP(t testing.TB, app, ns string) string {
	t.Helper()
	pods, err := K8sClient(t).CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=" + app,
	})
	if err != nil {
		t.Fatalf("listing pods app=%s in %s: %v", app, ns, err)
	}
	if len(pods.Items) == 0 {
		t.Fatalf("no pods found with app=%s in %s", app, ns)
	}
	return pods.Items[0].Status.HostIP
}

// AddSvcExternalIPs sets the service's spec.externalIPs.
func AddSvcExternalIPs(t testing.TB, svc, ns string, ips []string) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 30*time.Second, func() error {
		s, err := cs.CoreV1().Services(ns).Get(context.Background(), svc, metav1.GetOptions{})
		if err != nil {
			return err
		}
		s.Spec.ExternalIPs = ips
		_, err = cs.CoreV1().Services(ns).Update(context.Background(), s, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("adding external IPs %v to %s/%s: %v", ips, ns, svc, err)
	}
}
