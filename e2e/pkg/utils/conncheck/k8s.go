// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package conncheck

import (
	"context"
	"fmt"
	"maps"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

// deploy creates the server pod and (optionally) its service in the cluster.
// It reads all configuration from the Server struct fields.
func (s *Server) deploy(f *framework.Framework) (*v1.Pod, *v1.Service) {
	// Determine the image, args, and readiness probe based on the server type.
	var image string
	containers := []v1.Container{}
	servicePorts := []v1.ServicePort{}
	nodeselector := map[string]string{}

	if windows.ClusterIsWindows() {
		image = images.Porter
		nodeselector["kubernetes.io/os"] = "windows"
	} else if s.echoServer {
		image = images.EchoServer
		nodeselector["kubernetes.io/os"] = "linux"
	} else {
		image = images.TestWebserver
		nodeselector["kubernetes.io/os"] = "linux"
	}
	for _, port := range s.ports {
		args := []string{}
		env := []v1.EnvVar{}

		if windows.ClusterIsWindows() {
			env = []v1.EnvVar{
				{
					// porter (the windows server pod) uses the port value from the
					// env var name, it doesn't care about the env var value here
					Name:  fmt.Sprintf("SERVE_PORT_%d", port),
					Value: "value-not-used",
				},
			}
		} else if s.echoServer {
			// agnhost netexec serves HTTP on the specified port and returns
			// client IP at /clientip.
			args = []string{"netexec", fmt.Sprintf("--http-port=%d", port)}
		} else {
			args = []string{fmt.Sprintf("--port=%d", port)}
		}

		probePath := "/"
		if s.echoServer {
			probePath = "/clientip"
		}

		container := v1.Container{
			Name:            fmt.Sprintf("%s-container-%d", s.name, port),
			Image:           image,
			ImagePullPolicy: v1.PullIfNotPresent,
			Args:            args,
			Env:             env,
			Ports: []v1.ContainerPort{
				{
					ContainerPort: int32(port),
					Name:          fmt.Sprintf("serve-%d", port),
				},
			},
			ReadinessProbe: &v1.Probe{
				ProbeHandler: v1.ProbeHandler{
					HTTPGet: &v1.HTTPGetAction{
						Path: probePath,
						Port: intstr.IntOrString{
							IntVal: int32(port),
						},
						Scheme: v1.URISchemeHTTP,
					},
				},
			},
		}

		containers = append(containers, container)

		servicePorts = append(servicePorts, v1.ServicePort{
			Name:       fmt.Sprintf("%s-%d", s.name, port),
			Port:       int32(port),
			TargetPort: intstr.FromInt(port),
		})
	}

	newLabels := make(map[string]string)
	maps.Copy(newLabels, s.labels)
	newLabels["pod-name"] = s.name
	newLabels[roleLabel] = roleServer

	podCustomizer := s.composedPodCustomizer()
	svcCustomizer := s.composedSvcCustomizer()

	ginkgo.By(fmt.Sprintf("Creating a server pod %s in namespace %s", s.name, s.namespace.Name))
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   s.name,
			Labels: newLabels,
		},
		Spec: v1.PodSpec{
			Containers:    containers,
			RestartPolicy: v1.RestartPolicyNever,
			NodeSelector:  nodeselector,
			Tolerations: []v1.Toleration{
				{
					Key:      "kubernetes.io/arch",
					Operator: v1.TolerationOpEqual,
					Value:    "arm64",
					Effect:   v1.TaintEffectNoSchedule,
				},
			},
		},
	}
	if podCustomizer != nil {
		podCustomizer(pod)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pod, err := f.ClientSet.CoreV1().Pods(s.namespace.Name).Create(ctx, pod, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	logrus.Infof("Created pod %v", pod.Name)

	if !s.autoCreateSvc {
		return pod, nil
	}

	svcName := fmt.Sprintf("svc-%s", s.name)
	ginkgo.By(fmt.Sprintf("Creating a service %s for pod %s in namespace %s", svcName, s.name, s.namespace.Name))
	v4Svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svcName},
		Spec: v1.ServiceSpec{
			Ports:    servicePorts,
			Selector: map[string]string{"pod-name": s.name},
		},
	}

	if svcCustomizer != nil {
		svcCustomizer(v4Svc)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v4Svc, err = f.ClientSet.CoreV1().Services(s.namespace.Name).Create(ctx, v4Svc, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	if !pod.Spec.HostNetwork {
		// Create an ipv6 service for the pod instead, if the cluster supports v6.
		// If creation of this service succeeds, it will be used instead of the v4 only service.
		ipFamilies := []v1.IPFamily{v1.IPv6Protocol}
		v6SvcName := v6ServiceName(svcName)
		policy := v1.IPFamilyPolicyRequireDualStack

		svc := &v1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: v6SvcName},
			Spec: v1.ServiceSpec{
				Ports:          servicePorts,
				Selector:       map[string]string{"pod-name": s.name},
				IPFamilies:     ipFamilies,
				IPFamilyPolicy: &policy,
			},
		}
		if svcCustomizer != nil {
			svcCustomizer(svc)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		ginkgo.By(fmt.Sprintf("Creating a service %s for pod %s in namespace %s", v6SvcName, s.name, s.namespace.Name))
		v6Svc, err := f.ClientSet.CoreV1().Services(s.namespace.Name).Create(ctx, svc, metav1.CreateOptions{})
		if err == nil {
			return pod, v6Svc
		} else if !kerrors.IsInvalid(err) {
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Error creating IPv6 service")
		} else {
			// If v6 is not enabled on the cluster, we will receive an "Invalid" error type. In this case,
			// fall through and return the v4 service.
			logrus.WithField("svc", v4Svc.Name).Info("IPv6 not enabled, using v4 service")
		}
	}

	return pod, v4Svc
}

// v6ServiceName returns an ipv6 service name based on a ipv4 service name.
func v6ServiceName(name string) string {
	return name + "-ipv6"
}
