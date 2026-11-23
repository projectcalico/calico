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

package upgrade

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/jsonpath"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
)

// Get reads one object; ns "" means cluster-scoped.
func Get(ctx context.Context, e *Env, gvr schema.GroupVersionResource, ns, name string) (*unstructured.Unstructured, error) {
	if ns == "" {
		return e.Dynamic.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	}
	return e.Dynamic.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
}

// ExpectField checks that a JSONPath (e.g. "{.spec.natOutgoing}") on an
// object renders as fmt.Sprint(want).
func ExpectField(ctx context.Context, e *Env, gvr schema.GroupVersionResource, ns, name, path string, want any) error {
	obj, err := Get(ctx, e, gvr, ns, name)
	if err != nil {
		return fmt.Errorf("reading %s %s: %w", gvr.Resource, name, err)
	}
	jp := jsonpath.New("field")
	if err := jp.Parse(path); err != nil {
		return fmt.Errorf("jsonpath %q: %w", path, err)
	}
	var out bytes.Buffer
	if err := jp.Execute(&out, obj.Object); err != nil {
		return fmt.Errorf("%s %s %s: %w", gvr.Resource, name, path, err)
	}
	if got := out.String(); got != fmt.Sprint(want) {
		return fmt.Errorf("%s %s %s = %q, want %q", gvr.Resource, name, path, got, fmt.Sprint(want))
	}
	return nil
}

// PodsReady checks that the scenario namespace has pods matching selector
// and all of them are Ready.
func PodsReady(ctx context.Context, e *Env, selector string) error {
	pods, err := e.Kube.CoreV1().Pods(e.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return err
	}
	if len(pods.Items) == 0 {
		return fmt.Errorf("no pods match %q in %s", selector, e.Namespace)
	}
	for _, p := range pods.Items {
		ready := false
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		if !ready {
			return fmt.Errorf("pod %s is not Ready (phase %s)", p.Name, p.Status.Phase)
		}
	}
	return nil
}

// LogsContain reports whether any current container log of the pods matching
// selector in namespace has a line matching re since the given time.
func LogsContain(ctx context.Context, e *Env, namespace, selector string, re *regexp.Regexp, since time.Time) (bool, error) {
	pods, err := e.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return false, err
	}
	st := metav1.NewTime(since)
	for _, p := range pods.Items {
		for _, c := range p.Spec.Containers {
			raw, err := e.Kube.CoreV1().Pods(namespace).GetLogs(p.Name, &corev1.PodLogOptions{Container: c.Name, SinceTime: &st}).DoRaw(ctx)
			if err != nil {
				return false, fmt.Errorf("logs of %s/%s: %w", p.Name, c.Name, err)
			}
			if re.Match(raw) {
				return true, nil
			}
		}
	}
	return false, nil
}

// ExecCalicoNode runs a command in the calico-node container on node, for
// state probes can't see, such as BGP sessions ("birdcl show protocols").
func ExecCalicoNode(ctx context.Context, e *Env, node string, cmd ...string) (string, error) {
	pods, err := e.Kube.CoreV1().Pods(e.CalicoNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
		FieldSelector: "spec.nodeName=" + node,
	})
	if err != nil {
		return "", err
	}
	if len(pods.Items) != 1 {
		return "", fmt.Errorf("found %d calico-node pods on %s, want 1", len(pods.Items), node)
	}
	args := append([]string{"exec", pods.Items[0].Name, "-c", "calico-node", "--"}, cmd...)
	return e2ekubectl.RunKubectl(e.CalicoNamespace, args...)
}
