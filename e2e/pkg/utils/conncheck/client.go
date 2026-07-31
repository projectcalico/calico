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
	"io"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"

	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

// Client is a traffic source for connection checks. The default implementation
// is PodClient, a long-lived sleep pod running in the cluster; ExternalNodeClient
// runs commands over SSH on a host outside the cluster.
type Client interface {
	// ID returns a unique identifier for the client. For pod-backed clients
	// this is "<namespace>/<name>".
	ID() string

	// Name returns the human-readable name of the client.
	Name() string

	// Namespace returns the namespace the client lives in, or nil for
	// non-cluster clients.
	Namespace() *v1.Namespace

	// Pod returns the underlying pod, or nil for non-pod clients.
	Pod() *v1.Pod

	// Deploy creates the underlying resources (e.g. a sleep pod). Called by
	// ConnectionTester.Deploy. Safe to call multiple times; second call is a
	// no-op if already deployed.
	Deploy(ctx context.Context, f *framework.Framework) error

	// Cleanup tears down the resources created by Deploy.
	Cleanup(ctx context.Context, f *framework.Framework) error

	// WaitReady waits for the client to be ready to send traffic.
	WaitReady(ctx context.Context, f *framework.Framework) error

	// Exec runs a one-shot shell command on the client and returns the
	// combined output and an error if the command exited non-zero.
	Exec(ctx context.Context, cmd string) (string, error)

	// ExecStream runs a long-lived command, writing combined output to w.
	// Used for continuous probes (ExpectContinuously). Returns a stop
	// function that terminates the remote command and waits for the
	// streaming goroutine to drain.
	ExecStream(ctx context.Context, cmd []string, w io.Writer) (stop func() error, err error)
}

// NewClient builds a PodClient. Most tests should use this; for an external
// host see NewExternalNodeClient.
func NewClient(id string, ns *v1.Namespace, opts ...ClientOption) Client {
	if ns == nil {
		msg := fmt.Sprintf("Namespace is required for client %s", id)
		framework.Fail(msg, 1)
	}
	if id == "" {
		msg := fmt.Sprintf("ID is required for client in namespace %s", ns.Name)
		framework.Fail(msg, 1)
	}

	c := &PodClient{
		name:      id,
		namespace: ns,
	}
	for _, opt := range opts {
		_ = opt(c)
	}
	return c
}

// PodClient is a pod-backed Client.
type PodClient struct {
	name        string
	namespace   *v1.Namespace
	labels      map[string]string
	pod         *v1.Pod
	customizers []func(pod *v1.Pod)
}

// composedCustomizer returns a single customizer function that applies all
// registered customizers in order, or nil if none are registered.
func (c *PodClient) composedCustomizer() func(*v1.Pod) {
	if len(c.customizers) == 0 {
		return nil
	}
	return func(pod *v1.Pod) {
		for _, fn := range c.customizers {
			fn(pod)
		}
	}
}

func (c *PodClient) ID() string {
	return fmt.Sprintf("%s/%s", c.namespace.Name, c.name)
}

func (c *PodClient) Name() string {
	return c.name
}

func (c *PodClient) Namespace() *v1.Namespace {
	return c.namespace
}

func (c *PodClient) Pod() *v1.Pod {
	if c.pod == nil {
		msg := fmt.Sprintf("No pod is running for client %s/%s", c.namespace.Name, c.name)
		framework.Fail(msg, 1)
	}
	return c.pod
}

func (c *PodClient) Deploy(ctx context.Context, f *framework.Framework) error {
	if c.pod != nil {
		return nil
	}
	pod, err := CreateClientPod(f, c.namespace, c.name, c.labels, c.composedCustomizer())
	if err != nil {
		return err
	}
	c.pod = pod
	return nil
}

func (c *PodClient) WaitReady(ctx context.Context, f *framework.Framework) error {
	if c.pod == nil {
		return fmt.Errorf("PodClient %s/%s: WaitReady called before Deploy", c.namespace.Name, c.name)
	}
	if err := e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, c.pod.Name, c.pod.Namespace, podReadyTimeout(ctx)); err != nil {
		return err
	}
	// Refresh the pod so callers see NodeName / PodIP.
	p, err := f.ClientSet.CoreV1().Pods(c.namespace.Name).Get(ctx, c.pod.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	c.pod = p
	return nil
}

func (c *PodClient) Cleanup(ctx context.Context, f *framework.Framework) error {
	if c.pod == nil {
		return nil
	}
	err := f.ClientSet.CoreV1().Pods(c.namespace.Name).Delete(ctx, c.pod.Name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err := e2epod.WaitForPodNotFoundInNamespace(ctx, f.ClientSet, c.pod.Name, c.pod.Namespace, deletionTimeout); err != nil {
		return err
	}
	c.pod = nil
	return nil
}

func (c *PodClient) Exec(ctx context.Context, cmd string) (string, error) {
	return execShellInPod(c.Pod(), cmd)
}

func (c *PodClient) ExecStream(ctx context.Context, cmd []string, w io.Writer) (stop func() error, err error) {
	return execStreamInPod(ctx, c.Pod(), cmd, w)
}

type ClientOption func(*PodClient) error

func WithClientLabels(labels map[string]string) ClientOption {
	return func(c *PodClient) error {
		c.labels = labels
		return nil
	}
}

func WithClientCustomizer(customizer func(pod *v1.Pod)) ClientOption {
	return func(c *PodClient) error {
		c.customizers = append(c.customizers, customizer)
		return nil
	}
}

// WithCapture configures the client pod with NET_RAW and NET_ADMIN capabilities required
// for packet capture with tcpdump. Use this when calling ExpectEncrypted/ExpectPlaintext.
// Switches the image to netshoot which includes tcpdump and other network tools.
func WithCapture() ClientOption {
	return WithClientCustomizer(func(pod *v1.Pod) {
		if pod.Spec.SecurityContext == nil {
			pod.Spec.SecurityContext = &v1.PodSecurityContext{}
		}
		pod.Spec.SecurityContext.RunAsUser = ptrInt64(0)
		if len(pod.Spec.Containers) > 0 {
			c := &pod.Spec.Containers[0]
			c.Image = images.Netshoot
			if c.SecurityContext == nil {
				c.SecurityContext = &v1.SecurityContext{}
			}
			c.SecurityContext.RunAsUser = ptrInt64(0)
			if c.SecurityContext.Capabilities == nil {
				c.SecurityContext.Capabilities = &v1.Capabilities{}
			}
			c.SecurityContext.Capabilities.Add = append(
				c.SecurityContext.Capabilities.Add,
				"NET_RAW", "NET_ADMIN",
			)
		}
	})
}

func ptrInt64(v int64) *int64 { return &v }
