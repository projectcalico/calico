// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

func NewServer(name string, ns *v1.Namespace, opts ...ServerOption) *Server {
	if ns == nil {
		msg := fmt.Sprintf("Namespace is required for server %s", name)
		framework.Fail(msg, 1)
	}
	if name == "" {
		msg := fmt.Sprintf("Name is required for server in namespace %s", ns.Name)
		framework.Fail(msg, 1)
	}
	s := &Server{
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

type Server struct {
	name           string
	namespace      *v1.Namespace
	ports          []int
	labels         map[string]string
	pod            *v1.Pod
	service        *v1.Service
	podCustomizers []func(*v1.Pod)
	svcCustomizers []func(*v1.Service)
	autoCreateSvc  bool
}

// composedPodCustomizer returns a single customizer function that applies all
// registered pod customizers in order, or nil if none are registered.
func (s *Server) composedPodCustomizer() func(*v1.Pod) {
	if len(s.podCustomizers) == 0 {
		return nil
	}
	return func(pod *v1.Pod) {
		for _, c := range s.podCustomizers {
			c(pod)
		}
	}
}

// composedSvcCustomizer returns a single customizer function that applies all
// registered service customizers in order, or nil if none are registered.
func (s *Server) composedSvcCustomizer() func(*v1.Service) {
	if len(s.svcCustomizers) == 0 {
		return nil
	}
	return func(svc *v1.Service) {
		for _, c := range s.svcCustomizers {
			c(svc)
		}
	}
}

func (s *Server) ID() string {
	return fmt.Sprintf("%s/%s", s.namespace.Name, s.name)
}

func (s *Server) Name() string {
	return s.name
}

func (s *Server) Pod() *v1.Pod {
	if s.pod == nil {
		msg := fmt.Sprintf("No pod is running for server %s/%s", s.namespace.Name, s.name)
		framework.Fail(msg, 1)
	}
	return s.pod
}

func (s *Server) Service() *v1.Service {
	if s.service == nil {
		msg := fmt.Sprintf("No service is running for server %s/%s", s.namespace.Name, s.name)
		framework.Fail(msg, 1)
	}
	return s.service
}

// ClusterIPs returns a list of targets that can be used to connect to the service's ClusterIPs, if
// there are multiple (e.g., for dual-stack services).
func (s *Server) ClusterIPs(opts ...TargetOption) []Target {
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

// ClusterIP returns a target that can be used to connect to the service's Spec.ClusterIP.
// Most callers should use ClusterIPs() instead in order to test both IPv4 and IPv6 (when enabled).
func (s *Server) ClusterIP(opts ...TargetOption) Target {
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

func (s *Server) ClusterIPv4(opts ...TargetOption) Target {
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
	msg := fmt.Sprintf("No IPv4 ClusterIP found for server %s/%s", s.namespace.Name, s.name)
	framework.Fail(msg, 1)
	return nil
}

func (s *Server) ClusterIPv6(opts ...TargetOption) Target {
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
	msg := fmt.Sprintf("No IPv6 ClusterIP found for server %s/%s", s.namespace.Name, s.name)
	framework.Fail(msg, 1)
	return nil
}

// HostPorts returns a list of targets that can be used to connect to the pod's host IPs on the given port.
// It returns a target for each of the pod's host IPs, at the specified port.
func (s *Server) HostPorts(port int) []Target {
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

// NodePortPort returns port number of a NodePort service associated with the server.
func (s *Server) NodePortPort() int {
	svc := s.Service()
	if svc.Spec.Type != v1.ServiceTypeNodePort {
		msg := fmt.Sprintf("Service running for server %s/%s is not NodePort type", s.namespace.Name, s.name)
		framework.Fail(msg, 1)
	}

	return int(svc.Spec.Ports[0].NodePort)
}

// NodePort returns a target that can be used to connect to the service's NodePort.
// Callers should pass in the IP of a cluster node.
func (s *Server) NodePort(nodeIP string) Target {
	return &target{
		server:      s,
		targetType:  TypeNodePort,
		destination: nodeIP,
		port:        s.NodePortPort(),
		protocol:    TCP,
	}
}

// ICMP returns a target that can be used to connect to the pod's IP directly using ICMP.
func (s *Server) ICMP() Target {
	return &target{
		server:      s,
		targetType:  TypePodIP,
		destination: s.Pod().Status.PodIP,
		protocol:    ICMP,
	}
}

// ServiceDomain returns a target that can be used to connect to the service via DNS lookup.
func (s *Server) ServiceDomain(opts ...TargetOption) Target {
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

type ServerOption func(*Server) error

func WithServerLabels(labels map[string]string) ServerOption {
	return func(c *Server) error {
		c.labels = labels
		return nil
	}
}

func WithHostNetworking() ServerOption {
	return func(c *Server) error {
		c.podCustomizers = append(c.podCustomizers, func(pod *v1.Pod) {
			pod.Spec.HostNetwork = true
		})
		return nil
	}
}

func WithServerPodCustomizer(customizer func(*v1.Pod)) ServerOption {
	return func(c *Server) error {
		c.podCustomizers = append(c.podCustomizers, customizer)
		return nil
	}
}

func WithServerSvcCustomizer(customizer func(*v1.Service)) ServerOption {
	return func(c *Server) error {
		c.svcCustomizers = append(c.svcCustomizers, customizer)
		return nil
	}
}

func WithPorts(ports ...int) ServerOption {
	return func(c *Server) error {
		c.ports = ports
		return nil
	}
}

func WithAutoCreateService(autoCreate bool) ServerOption {
	return func(c *Server) error {
		c.autoCreateSvc = autoCreate
		return nil
	}
}
