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

package v1_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	libtestutils "github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var (
	testEnv      *testutils.TestEnv
	schemaClient ctrlclient.Client
)

func TestMain(m *testing.M) {
	repoRoot := libtestutils.FindRepoRoot()
	crdPath := filepath.Join(repoRoot, "kube-controllers", "pkg", "apis", "migration", "v1", "crd")

	var err error
	testEnv, err = testutils.NewTestEnv(crdPath)
	if err != nil {
		panic(err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := migrationv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	schemaClient, err = ctrlclient.New(testEnv.RestConfig, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		panic(err)
	}

	rc := m.Run()
	if err := testEnv.Stop(); err != nil {
		panic(err)
	}
	os.Exit(rc)
}

// newMigration builds a valid DatastoreMigration. Each test uses a distinct name
// because the resource is cluster-scoped and envtest is shared across tests.
func newMigration(name string) *migrationv1.DatastoreMigration {
	return &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: migrationv1.DatastoreMigrationSpec{
			Type: migrationv1.DatastoreMigrationTypeAPIServerToCRDs,
		},
	}
}

// TestSpecTypeIsImmutable checks that spec.type can be set at create time but
// not changed afterwards. The migration is a one-shot operation; switching type
// mid-flight has no coherent meaning.
func TestSpecTypeIsImmutable(t *testing.T) {
	ctx := context.Background()
	m := newMigration("immutable-type")
	if err := schemaClient.Create(ctx, m); err != nil {
		t.Fatalf("create with a valid type should be accepted: %v", err)
	}
	defer func() { _ = schemaClient.Delete(ctx, m) }()

	m.Spec.Type = migrationv1.DatastoreMigrationType("SomethingElse")
	err := schemaClient.Update(ctx, m)
	if err == nil {
		t.Fatal("expected the update to be rejected, spec.type should be immutable")
	}
	if !hasNonEnumFieldError(err, "spec.type") {
		t.Fatalf("update was rejected by the spec.type enum alone, no immutability rule fired: %v", err)
	}
}

// hasNonEnumFieldError reports whether err carries a validation cause on field
// that is something other than the enum's "unsupported value" complaint.
// spec.type is enum constrained to a single value, so the enum rejects any
// changed value on its own; only a second cause on the same field proves a
// transition rule rejected the update too.
func hasNonEnumFieldError(err error, field string) bool {
	var statusErr kerrors.APIStatus
	if !errors.As(err, &statusErr) {
		return false
	}

	details := statusErr.Status().Details
	if details == nil {
		return false
	}
	for _, cause := range details.Causes {
		if cause.Field == field && cause.Type != metav1.CauseTypeFieldValueNotSupported {
			return true
		}
	}
	return false
}

// TestPhaseEnumIsEnforced checks that status.phase only accepts the six phases
// the state machine defines.
func TestPhaseEnumIsEnforced(t *testing.T) {
	ctx := context.Background()
	m := newMigration("phase-enum")
	if err := schemaClient.Create(ctx, m); err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = schemaClient.Delete(ctx, m) }()

	for _, phase := range []migrationv1.DatastoreMigrationPhase{
		migrationv1.DatastoreMigrationPhasePending,
		migrationv1.DatastoreMigrationPhaseMigrating,
		migrationv1.DatastoreMigrationPhaseWaitingForConflictResolution,
		migrationv1.DatastoreMigrationPhaseConverged,
		migrationv1.DatastoreMigrationPhaseComplete,
		migrationv1.DatastoreMigrationPhaseFailed,
	} {
		m.Status.Phase = phase
		if err := schemaClient.Status().Update(ctx, m); err != nil {
			t.Errorf("phase %q should be accepted: %v", phase, err)
		}
	}

	m.Status.Phase = migrationv1.DatastoreMigrationPhase("Bogus")
	if err := schemaClient.Status().Update(ctx, m); err == nil {
		t.Fatal("expected an out-of-enum phase to be rejected")
	}
}

// TestConditionsMergeByType checks that two writers touching different
// conditions don't clobber each other. Without listType=map on the conditions
// list, server-side apply treats it as atomic and the second writer wins
// outright.
func TestConditionsMergeByType(t *testing.T) {
	ctx := context.Background()
	m := newMigration("conditions-merge")
	if err := schemaClient.Create(ctx, m); err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = schemaClient.Delete(ctx, m) }()

	now := metav1.Now()
	applyCondition := func(fieldOwner, condType string) error {
		patch := &migrationv1.DatastoreMigration{
			TypeMeta: metav1.TypeMeta{
				Kind:       "DatastoreMigration",
				APIVersion: migrationv1.SchemeGroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{Name: m.Name},
			Status: migrationv1.DatastoreMigrationStatus{
				Conditions: []metav1.Condition{{
					Type:               condType,
					Status:             metav1.ConditionTrue,
					Reason:             "Testing",
					Message:            "set by " + fieldOwner,
					LastTransitionTime: now,
				}},
			},
		}
		return schemaClient.Status().Patch(ctx, patch, ctrlclient.Apply,
			ctrlclient.FieldOwner(fieldOwner), ctrlclient.ForceOwnership)
	}

	if err := applyCondition("writer-a", "Conflicted"); err != nil {
		t.Fatalf("writer-a apply: %v", err)
	}
	if err := applyCondition("writer-b", "Degraded"); err != nil {
		t.Fatalf("writer-b apply: %v", err)
	}

	got := &migrationv1.DatastoreMigration{}
	if err := schemaClient.Get(ctx, ctrlclient.ObjectKey{Name: m.Name}, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Status.Conditions) != 2 {
		t.Fatalf("expected both conditions to survive, got %d: %+v", len(got.Status.Conditions), got.Status.Conditions)
	}
}
