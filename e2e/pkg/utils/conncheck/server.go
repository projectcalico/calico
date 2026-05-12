// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package conncheck

import (
	"context"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
)

// Server is a traffic destination for connection checks. The default
// implementation is PodServer; VMServer wraps a KubeVirt VirtualMachineInstance.
type Server interface {
	ID() string
	Name() string
	Namespace() *v1.Namespace
	Pod() *v1.Pod
	Service() *v1.Service

	// Target builders.
	ClusterIPs(opts ...TargetOption) []Target
	ClusterIP(opts ...TargetOption) Target
	ClusterIPv4(opts ...TargetOption) Target
	ClusterIPv6(opts ...TargetOption) Target
	HostPorts(port int) []Target
	NodePortPort() int
	NodePort(nodeIP string, opts ...TargetOption) Target
	ICMP() Target
	ServiceDomain(opts ...TargetOption) Target

	// Lifecycle.
	Deploy(ctx context.Context, f *framework.Framework) error
	Cleanup(ctx context.Context, f *framework.Framework) error
	WaitReady(ctx context.Context, f *framework.Framework) error
}

func NewServer(name string, ns *v1.Namespace, opts ...ServerOption) Server {
	if ns == nil {
		framework.Fail(fmt.Sprintf("Namespace is required for server %s", name), 1)
	}
	if name == "" {
		framework.Fail(fmt.Sprintf("Name is required for server in namespace %s", ns.Name), 1)
	}
	s := &PodServer{
		name:          name,
		namespace:     ns,
		ports:         []int{80},
		autoCreateSvc: true,
	}
	for _, opt := range opts {
		_ = opt(s)
	}
	return s
}

// PodServer is a pod-backed Server.
type PodServer struct {
	name           string
	namespace      *v1.Namespace
	ports          []int
	labels         map[string]string
	pod            *v1.Pod
	service        *v1.Service
	podCustomizers []func(*v1.Pod)
	svcCustomizers []func(*v1.Service)
	autoCreateSvc  bool
	echoServer     bool
}

func (s *PodServer) composedPodCustomizer() func(*v1.Pod) {
	if len(s.podCustomizers) == 0 {
		return nil
	}
	return func(pod *v1.Pod) {
		for _, c := range s.podCustomizers {
			c(pod)
		}
	}
}

func (s *PodServer) composedSvcCustomizer() func(*v1.Service) {
	if len(s.svcCustomizers) == 0 {
		return nil
	}
	return func(svc *v1.Service) {
		for _, c := range s.svcCustomizers {
			c(svc)
		}
	}
}

func (s *PodServer) ID() string               { return fmt.Sprintf("%s/%s", s.namespace.Name, s.name) }
func (s *PodServer) Name() string             { return s.name }
func (s *PodServer) Namespace() *v1.Namespace { return s.namespace }

func (s *PodServer) Pod() *v1.Pod {
	if s.pod == nil {
		framework.Fail(fmt.Sprintf("No pod is running for server %s/%s", s.namespace.Name, s.name), 1)
	}
	return s.pod
}

func (s *PodServer) Service() *v1.Service {
	if s.service == nil {
		framework.Fail(fmt.Sprintf("No service is running for server %s/%s", s.namespace.Name, s.name), 1)
	}
	return s.service
}

func (s *PodServer) Deploy(ctx context.Context, f *framework.Framework) error {
	if s.pod != nil {
		return nil
	}
	pod, svc, err := s.create(ctx, f)
	if err != nil {
		return err
	}
	s.pod = pod
	s.service = svc
	return nil
}

func (s *PodServer) WaitReady(ctx context.Context, f *framework.Framework) error {
	if s.pod == nil {
		return fmt.Errorf("PodServer %s/%s: WaitReady called before Deploy", s.namespace.Name, s.name)
	}
	if err := e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, s.pod.Name, s.pod.Namespace, podReadyTimeout(ctx)); err != nil {
		return err
	}
	p, err := f.ClientSet.CoreV1().Pods(s.namespace.Name).Get(ctx, s.pod.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	s.pod = p
	return nil
}

func (s *PodServer) Cleanup(ctx context.Context, f *framework.Framework) error {
	if s.pod != nil {
		err := f.ClientSet.CoreV1().Pods(s.namespace.Name).Delete(ctx, s.pod.Name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err := e2epod.WaitForPodNotFoundInNamespace(ctx, f.ClientSet, s.pod.Name, s.pod.Namespace, deletionTimeout); err != nil {
			return err
		}
		s.pod = nil
	}
	if s.service != nil {
		err := f.ClientSet.CoreV1().Services(s.namespace.Name).Delete(ctx, s.service.Name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		s.service = nil
	}
	return nil
}

// ClusterIPs returns one target per ClusterIP on the underlying service (dual-stack capable).
func (s *PodServer) ClusterIPs(opts ...TargetOption) []Target {
	var targets []Target
	for _, ip := range s.Service().Spec.ClusterIPs {
		t := &target{
			server:      s,
			targetType:  TypeClusterIP,
			destination: ip,
			protocol:    TCP,
		}
		for _, opt := range opts {
			if err := opt(t); err != nil {
				framework.ExpectNoError(err)
			}
		}
		targets = append(targets, t)
	}
	return targets
}

// ClusterIP returns a target for the service's primary ClusterIP. Most callers
// should use ClusterIPs() to cover IPv4 and IPv6.
func (s *PodServer) ClusterIP(opts ...TargetOption) Target {
	t := &target{
		server:      s,
		targetType:  TypeClusterIP,
		destination: s.Service().Spec.ClusterIP,
		protocol:    TCP,
	}
	for _, opt := range opts {
		if err := opt(t); err != nil {
			framework.ExpectNoError(err)
		}
	}
	return t
}

func (s *PodServer) ClusterIPv4(opts ...TargetOption) Target {
	for _, ip := range s.Service().Spec.ClusterIPs {
		if strings.Contains(ip, ":") {
			continue
		}
		t := &target{
			server:      s,
			targetType:  TypeClusterIP,
			destination: ip,
			protocol:    TCP,
		}
		for _, opt := range opts {
			if err := opt(t); err != nil {
				framework.ExpectNoError(err)
			}
		}
		return t
	}
	framework.Fail(fmt.Sprintf("No IPv4 ClusterIP found for server %s/%s", s.namespace.Name, s.name), 1)
	return nil
}

func (s *PodServer) ClusterIPv6(opts ...TargetOption) Target {
	for _, ip := range s.Service().Spec.ClusterIPs {
		if !strings.Contains(ip, ":") {
			continue
		}
		t := &target{
			server:      s,
			targetType:  TypeClusterIP,
			destination: ip,
			protocol:    TCP,
		}
		for _, opt := range opts {
			if err := opt(t); err != nil {
				framework.ExpectNoError(err)
			}
		}
		return t
	}
	framework.Fail(fmt.Sprintf("No IPv6 ClusterIP found for server %s/%s", s.namespace.Name, s.name), 1)
	return nil
}

// HostPorts returns one target per host IP at the given port.
func (s *PodServer) HostPorts(port int) []Target {
	var targets []Target
	for _, hostIP := range s.Pod().Status.HostIPs {
		targets = append(targets, &target{
			server:      s,
			targetType:  TypePodIP,
			destination: hostIP.IP,
			port:        port,
			protocol:    TCP,
		})
	}
	return targets
}

func (s *PodServer) NodePortPort() int {
	svc := s.Service()
	if svc.Spec.Type != v1.ServiceTypeNodePort {
		framework.Fail(fmt.Sprintf("Service running for server %s/%s is not NodePort type", s.namespace.Name, s.name), 1)
	}
	return int(svc.Spec.Ports[0].NodePort)
}

func (s *PodServer) NodePort(nodeIP string, opts ...TargetOption) Target {
	t := &target{
		server:      s,
		targetType:  TypeNodePort,
		destination: nodeIP,
		port:        s.NodePortPort(),
		protocol:    TCP,
	}
	for _, opt := range opts {
		if err := opt(t); err != nil {
			framework.ExpectNoError(err)
		}
	}
	return t
}

func (s *PodServer) ICMP() Target {
	return &target{
		server:      s,
		targetType:  TypePodIP,
		destination: s.Pod().Status.PodIP,
		protocol:    ICMP,
	}
}

func (s *PodServer) ServiceDomain(opts ...TargetOption) Target {
	t := &target{
		server:      s,
		targetType:  TypeService,
		destination: fmt.Sprintf("%s.%s", s.Service().Name, s.Service().Namespace),
		protocol:    TCP,
	}
	for _, opt := range opts {
		if err := opt(t); err != nil {
			framework.ExpectNoError(err)
		}
	}
	return t
}

type ServerOption func(*PodServer) error

func WithServerLabels(labels map[string]string) ServerOption {
	return func(c *PodServer) error {
		c.labels = labels
		return nil
	}
}

func WithHostNetworking() ServerOption {
	return func(c *PodServer) error {
		c.podCustomizers = append(c.podCustomizers, func(pod *v1.Pod) {
			pod.Spec.HostNetwork = true
		})
		return nil
	}
}

func WithServerPodCustomizer(customizer func(*v1.Pod)) ServerOption {
	return func(c *PodServer) error {
		c.podCustomizers = append(c.podCustomizers, customizer)
		return nil
	}
}

func WithServerSvcCustomizer(customizer func(*v1.Service)) ServerOption {
	return func(c *PodServer) error {
		c.svcCustomizers = append(c.svcCustomizers, customizer)
		return nil
	}
}

func WithPorts(ports ...int) ServerOption {
	return func(c *PodServer) error {
		c.ports = ports
		return nil
	}
}

func WithAutoCreateService(autoCreate bool) ServerOption {
	return func(c *PodServer) error {
		c.autoCreateSvc = autoCreate
		return nil
	}
}

// WithEchoServer switches the server image to agnhost netexec. Its /clientip
// endpoint returns the client address, useful for SNAT detection.
func WithEchoServer() ServerOption {
	return func(c *PodServer) error {
		c.echoServer = true
		return nil
	}
}

func WithNodePortService() ServerOption {
	return func(c *PodServer) error {
		c.svcCustomizers = append(c.svcCustomizers, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeNodePort
		})
		return nil
	}
}

func WithExternalIP(ip string) ServerOption {
	return func(c *PodServer) error {
		c.svcCustomizers = append(c.svcCustomizers, func(svc *v1.Service) {
			svc.Spec.ExternalIPs = append(svc.Spec.ExternalIPs, ip)
		})
		return nil
	}
}

func WithExternalTrafficPolicy(policy v1.ServiceExternalTrafficPolicy) ServerOption {
	return func(c *PodServer) error {
		c.svcCustomizers = append(c.svcCustomizers, func(svc *v1.Service) {
			svc.Spec.ExternalTrafficPolicy = policy
		})
		return nil
	}
}
