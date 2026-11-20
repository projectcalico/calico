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
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The CI migrate phase writes the window; keep these names in step with
// .argoci/scripts/phases/migrate.sh.
const (
	windowNamespace = "e2e-upgrade-system"
	windowConfigMap = "upgrade-window"
	recordConfigMap = "seed-record"
	recordKey       = "record.json"
)

// Record is what seed leaves for verify, in ConfigMap seed-record in the
// scenario namespace. It is written last, so its absence means seed failed.
type Record struct {
	SeededAt    time.Time `json:"seededAt"`
	FromVersion string    `json:"fromVersion"`
	Objects     []ObjRef  `json:"objects"`
	// ProberUIDs and ProbeWarmAt let verify tell a prober that ran throughout
	// from one that was replaced, and where each Before slice starts.
	ProberUIDs  map[string]string    `json:"proberUIDs"`
	ProbeWarmAt map[string]time.Time `json:"probeWarmAt"`
	// Values belong to the scenario.
	Values map[string]string `json:"values"`
}

func writeRecord(ctx context.Context, kube kubernetes.Interface, ns string, r *Record) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: recordConfigMap, Namespace: ns},
		Data:       map[string]string{recordKey: string(data)},
	}
	_, err = kube.CoreV1().ConfigMaps(ns).Create(ctx, cm, metav1.CreateOptions{})
	return err
}

func readRecord(ctx context.Context, kube kubernetes.Interface, ns string) (*Record, error) {
	cm, err := kube.CoreV1().ConfigMaps(ns).Get(ctx, recordConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("no seed record in %s: the seed phase failed or never ran; see junit-upgrade-seed.xml and upgrade-seed-tests.log", ns)
	}
	if err != nil {
		return nil, err
	}
	r := &Record{}
	if err := json.Unmarshal([]byte(cm.Data[recordKey]), r); err != nil {
		return nil, fmt.Errorf("seed record in %s: %w", ns, err)
	}
	return r, nil
}

func readWindow(ctx context.Context, kube kubernetes.Interface) (Window, error) {
	cm, err := kube.CoreV1().ConfigMaps(windowNamespace).Get(ctx, windowConfigMap, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return Window{}, fmt.Errorf("no %s/%s ConfigMap: the CI migrate phase didn't record the upgrade window", windowNamespace, windowConfigMap)
	}
	if err != nil {
		return Window{}, err
	}
	var w Window
	if w.Start, err = time.Parse(time.RFC3339, cm.Data["start"]); err != nil {
		return Window{}, fmt.Errorf("upgrade window start: %w", err)
	}
	if w.End, err = time.Parse(time.RFC3339, cm.Data["end"]); err != nil {
		return Window{}, fmt.Errorf("upgrade window end (the upgrade may not have finished): %w", err)
	}
	w.Failed = cm.Data["result"] != "succeeded"
	if w.End.Before(w.Start) {
		return Window{}, fmt.Errorf("upgrade window ends (%s) before it starts (%s)", w.End, w.Start)
	}
	return w, nil
}

// calicoNamespace finds where calico-node runs, which differs by installer.
func calicoNamespace(ctx context.Context, kube kubernetes.Interface) (string, error) {
	for _, ns := range []string{"calico-system", "kube-system"} {
		_, err := kube.AppsV1().DaemonSets(ns).Get(ctx, "calico-node", metav1.GetOptions{})
		if err == nil {
			return ns, nil
		}
		if !apierrors.IsNotFound(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("no calico-node DaemonSet in calico-system or kube-system")
}

func isNotFound(err error) bool { return apierrors.IsNotFound(err) }
