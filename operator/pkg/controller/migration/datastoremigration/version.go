// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package datastoremigration

import (
	"context"
	"fmt"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	initialRetry = 1 * time.Second
	maxRetry     = 30 * time.Second
)

var log = ctrl.Log.WithName("datastoremigration")

var (
	servedMutex   sync.RWMutex
	servedVersion = GroupVersionV1
)

// ServedVersion returns the group/version the operator reads DatastoreMigration at. It is v1
// until WaitForServedVersion finds out what the cluster serves.
func ServedVersion() schema.GroupVersion {
	servedMutex.RLock()
	defer servedMutex.RUnlock()
	return servedVersion
}

// WaitForServedVersion records the served version once the CRD appears. The user installs it
// at migration time, so expect a wait.
func WaitForServedVersion(ctx context.Context, disco discovery.DiscoveryInterface) {
	delay := initialRetry
	for {
		gv, ok, err := ServedGroupVersion(disco)
		switch {
		case err != nil:
			log.Error(err, "Failed to look up served DatastoreMigration versions - will retry")
		case ok:
			servedMutex.Lock()
			servedVersion = gv
			servedMutex.Unlock()
			log.Info("Resolved served DatastoreMigration version", "groupVersion", gv)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, maxRetry)
	}
}

// ServedGroupVersion returns the served group/version, preferring v1. The bool is false when
// the CRD isn't installed; a failed lookup errors.
func ServedGroupVersion(disco discovery.DiscoveryInterface) (schema.GroupVersion, bool, error) {
	for _, gv := range []schema.GroupVersion{GroupVersionV1, GroupVersionV1beta1} {
		resources, err := disco.ServerResourcesForGroupVersion(gv.String())
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return schema.GroupVersion{}, false, fmt.Errorf("look up %s: %w", gv, err)
		}
		for _, r := range resources.APIResources {
			if r.Name == Resource {
				return gv, true, nil
			}
		}
	}
	return schema.GroupVersion{}, false, nil
}

// WatchObject returns an empty DatastoreMigration at the served version, for controllers
// registering a watch.
func WatchObject() client.Object {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(ServedVersion().WithKind(Kind))
	return u
}
