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

package conncheck

import (
	"context"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

// VMServer wraps a KubeVirt VirtualMachineInstance as a Server. The test is
// expected to create the VMI itself; this just locates the virt-launcher pod
// (which shares the VM's netns, so its PodIP is the VM's IP) and exposes the
// pod-IP-based Target builders.
//
// NewVMServer does not create or own the VMI; Cleanup is a no-op.
type VMServer struct {
	name      string
	namespace *v1.Namespace
	vmi       *kubevirtv1.VirtualMachineInstance
	pod       *v1.Pod
}

func NewVMServer(vmi *kubevirtv1.VirtualMachineInstance) Server {
	if vmi == nil {
		framework.Fail("NewVMServer: vmi is required", 1)
	}
	return &VMServer{
		name:      vmi.Name,
		namespace: &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: vmi.Namespace}},
		vmi:       vmi,
	}
}

func (s *VMServer) ID() string {
	return fmt.Sprintf("%s/%s", s.namespace.Name, s.name)
}

func (s *VMServer) Name() string {
	return s.name
}

func (s *VMServer) Namespace() *v1.Namespace {
	return s.namespace
}

func (s *VMServer) Service() *v1.Service {
	return nil
}

func (s *VMServer) Pod() *v1.Pod {
	if s.pod == nil {
		framework.Fail(fmt.Sprintf("VMServer %s: no launcher pod resolved; call Deploy first", s.ID()), 1)
	}
	return s.pod
}

// Deploy resolves the virt-launcher pod for the underlying VMI.
func (s *VMServer) Deploy(ctx context.Context, f *framework.Framework) error {
	return s.resolveLauncher(ctx, f)
}

// Cleanup is a no-op; the test owns the VMI lifecycle.
func (s *VMServer) Cleanup(_ context.Context, _ *framework.Framework) error {
	return nil
}

func (s *VMServer) WaitReady(ctx context.Context, f *framework.Framework) error {
	if s.pod == nil {
		if err := s.resolveLauncher(ctx, f); err != nil {
			return err
		}
	}
	if err := e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, s.pod.Name, s.pod.Namespace, podReadyTimeout(ctx)); err != nil {
		return err
	}
	p, err := f.ClientSet.CoreV1().Pods(s.pod.Namespace).Get(ctx, s.pod.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	s.pod = p
	return nil
}

// resolveLauncher polls for the virt-launcher pod matching this VMI.
func (s *VMServer) resolveLauncher(ctx context.Context, f *framework.Framework) error {
	deadline := time.Now().Add(podReadyTimeout(ctx))
	selector := fmt.Sprintf("%s=%s", kubevirtv1.CreatedByLabel, string(s.vmi.UID))
	var lastErr error
	for {
		pods, err := f.ClientSet.CoreV1().Pods(s.namespace.Name).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			lastErr = err
		} else {
			for i := range pods.Items {
				p := &pods.Items[i]
				if p.DeletionTimestamp != nil {
					continue
				}
				s.pod = p
				return nil
			}
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("VMServer %s: launcher pod not found via %q (last list error: %w)", s.ID(), selector, lastErr)
			}
			return fmt.Errorf("VMServer %s: launcher pod not found via %q", s.ID(), selector)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// noService fails with a useful message; service-based targets aren't supported.
func (s *VMServer) noService(method string) Target {
	framework.Failf("VMServer %s: %s requires a Service. Use ICMP() or HostPorts() against the VM's PodIP.", s.ID(), method)
	return nil
}

func (s *VMServer) ClusterIPs(_ ...TargetOption) []Target {
	_ = s.noService("ClusterIPs")
	return nil
}

func (s *VMServer) ClusterIP(_ ...TargetOption) Target {
	return s.noService("ClusterIP")
}

func (s *VMServer) ClusterIPv4(_ ...TargetOption) Target {
	return s.noService("ClusterIPv4")
}

func (s *VMServer) ClusterIPv6(_ ...TargetOption) Target {
	return s.noService("ClusterIPv6")
}

func (s *VMServer) NodePortPort() int {
	framework.Failf("VMServer %s: NodePortPort requires a Service", s.ID())
	return 0
}

func (s *VMServer) NodePort(_ string, _ ...TargetOption) Target {
	return s.noService("NodePort")
}

func (s *VMServer) ServiceDomain(_ ...TargetOption) Target {
	return s.noService("ServiceDomain")
}

// HostPorts returns one target per host IP of the launcher pod at the given port.
func (s *VMServer) HostPorts(port int) []Target {
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

// ICMP returns a target pinging the VM's PodIP (the launcher pod's PodIP).
func (s *VMServer) ICMP() Target {
	return &target{
		server:      s,
		targetType:  TypePodIP,
		destination: s.Pod().Status.PodIP,
		protocol:    ICMP,
	}
}

// TCPPodIP returns a TCP target at the VM's PodIP and given port.
func (s *VMServer) TCPPodIP(port int) Target {
	return &target{
		server:      s,
		targetType:  TypePodIP,
		destination: s.Pod().Status.PodIP,
		port:        port,
		protocol:    TCP,
	}
}
