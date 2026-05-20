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
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

// create builds the server pod and (optionally) its service. The caller stores
// the returned objects on the PodServer.
func (s *PodServer) create(ctx context.Context, f *framework.Framework) (*v1.Pod, *v1.Service, error) {
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
					// env var name; the env var value is ignored.
					Name:  fmt.Sprintf("SERVE_PORT_%d", port),
					Value: "value-not-used",
				},
			}
		} else if s.echoServer {
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
						Path:   probePath,
						Port:   intstr.IntOrString{IntVal: int32(port)},
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
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pod, err := f.ClientSet.CoreV1().Pods(s.namespace.Name).Create(cctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}
	logrus.Infof("Created pod %v", pod.Name)

	if !s.autoCreateSvc {
		return pod, nil, nil
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
	cctx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel2()
	v4Svc, err = f.ClientSet.CoreV1().Services(s.namespace.Name).Create(cctx2, v4Svc, metav1.CreateOptions{})
	if err != nil {
		return nil, nil, err
	}

	if !pod.Spec.HostNetwork {
		// Try a v6 service. If the cluster doesn't support v6 we'll get an
		// Invalid error; fall through and use the v4 service.
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
		cctx3, cancel3 := context.WithTimeout(ctx, 30*time.Second)
		defer cancel3()

		ginkgo.By(fmt.Sprintf("Creating a service %s for pod %s in namespace %s", v6SvcName, s.name, s.namespace.Name))
		v6Svc, err := f.ClientSet.CoreV1().Services(s.namespace.Name).Create(cctx3, svc, metav1.CreateOptions{})
		if err == nil {
			return pod, v6Svc, nil
		} else if !kerrors.IsInvalid(err) {
			return nil, nil, fmt.Errorf("error creating IPv6 service: %w", err)
		}
		logrus.WithField("svc", v4Svc.Name).Info("IPv6 not enabled, using v4 service")
	}

	return pod, v4Svc, nil
}

func v6ServiceName(name string) string {
	return name + "-ipv6"
}
