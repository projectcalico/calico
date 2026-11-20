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

package scenarios

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/onsi/ginkgo/v2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/tests/upgrade"
)

//go:embed testdata/crd-invalid-stored
var crdInvalidFS embed.FS

// Objects stored under older, looser validation must stay readable and
// deletable once stricter CRD rules are installed over them, and must not
// disturb how valid policy is enforced. An object a user can neither fix nor
// delete after an upgrade is release-blocking.
func init() {
	upgrade.Register(upgrade.Scenario{
		Name:     "crd-invalid-stored",
		Feature:  "NetworkPolicy",
		From:     []string{"v3.32", "v3.33"},
		Fixtures: upgrade.Sub(crdInvalidFS, "testdata/crd-invalid-stored"),
		Probes: []upgrade.Probe{
			{Name: "client", Client: "client", Target: "svc:target:80", Protocol: "tcp", Expect: upgrade.AlwaysAllowed},
			{Name: "blocked", Client: "blocked", Target: "svc:target:80", Protocol: "tcp", Expect: upgrade.AlwaysDenied},
		},
		Seed:   seedInvalidObjects,
		Verify: verifyInvalidObjects,
	})
}

// seedInvalidObjects stores whatever the from-stream accepts. Which objects
// that is varies by stream and is not itself the test.
func seedInvalidObjects(ctx context.Context, e *upgrade.Env) error {
	objs, err := upgrade.Objects(upgrade.Sub(crdInvalidFS, "testdata/crd-invalid-stored/seeds"))
	if err != nil {
		return err
	}
	var seeds []upgrade.ObjRef
	for _, o := range objs {
		ref, err := upgrade.Create(ctx, e, o)
		// A leftover from an earlier failed run isn't a rejection; counting it
		// as one would silently shrink the corpus.
		if apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("%s %s is left from an earlier run; delete it and re-seed: %w", o.GetKind(), o.GetName(), err)
		}
		if err != nil {
			framework.Logf("from-stream rejected %s %s: %v", o.GetKind(), o.GetName(), err)
			continue
		}
		seeds = append(seeds, ref)
	}
	framework.Logf("stored %d of %d invalid objects", len(seeds), len(objs))
	data, err := json.Marshal(seeds)
	if err != nil {
		return err
	}
	e.Record.Values["seeds"] = string(data)
	return nil
}

func verifyInvalidObjects(ctx context.Context, e *upgrade.Env) error {
	var seeds []upgrade.ObjRef
	if err := json.Unmarshal([]byte(e.Record.Values["seeds"]), &seeds); err != nil {
		return fmt.Errorf("seed record seeds: %w", err)
	}
	if len(seeds) == 0 {
		framework.Logf("the from-stream rejected every object; only the probes test this upgrade")
		return nil
	}

	var errs []error
	for _, s := range seeds {
		gvr, _, err := upgrade.Resource(e, s.APIVersion, s.Kind)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		res := e.Dynamic.Resource(gvr).Namespace(s.Namespace)

		ginkgo.By(fmt.Sprintf("Reading, touching and deleting stored %s %s", s.Kind, s.Name))
		if _, err := res.Get(ctx, s.Name, metav1.GetOptions{}); err != nil {
			errs = append(errs, fmt.Errorf("%s %s is no longer readable: %w", s.Kind, s.Name, err))
			continue
		}

		// Ratcheting admits metadata-only updates on some kinds and the webhook
		// rejects them on others; either is acceptable, so only log it.
		patch := []byte(`{"metadata":{"labels":{"crdv":"touched"}}}`)
		if _, err := res.Patch(ctx, s.Name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			framework.Logf("label update on stored %s %s rejected: %v", s.Kind, s.Name, err)
		} else {
			framework.Logf("label update on stored %s %s accepted", s.Kind, s.Name)
		}

		if err := res.Delete(ctx, s.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("%s %s can't be deleted: %w", s.Kind, s.Name, err))
			continue
		}
		if err := wait.PollUntilContextTimeout(ctx, time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
			_, err := res.Get(ctx, s.Name, metav1.GetOptions{})
			return apierrors.IsNotFound(err), nil
		}); err != nil {
			errs = append(errs, fmt.Errorf("%s %s still exists a minute after a successful delete", s.Kind, s.Name))
		}
	}
	return errors.Join(errs...)
}
