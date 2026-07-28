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

//go:build pickerdemo

// This file is a developer harness, compiled only under the `pickerdemo` build
// tag, so the cmd/pickerdemo program can drive the (unexported) interactive
// picker against a fake clientset. It is excluded from all normal builds; use it
// to eyeball the picker against arbitrarily large fake clusters. A normal test
// (TestPickerDemoBuilds) keeps it compiling.

package cluster

import "k8s.io/client-go/kubernetes"

// RunInteractiveSelectionDemo runs the interactive node picker against the given
// clientset and returns the chosen problem/comparison nodes.
func RunInteractiveSelectionDemo(kubeClient kubernetes.Interface) (problem, comparison []string, proceed bool, err error) {
	sel, ok, e := runInteractiveSelection(kubeClient)
	return sel.ProblemNodes, sel.ComparisonNodes, ok, e
}
