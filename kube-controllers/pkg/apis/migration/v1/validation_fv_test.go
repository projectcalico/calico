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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	libtestutils "github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var (
	schemaClient ctrlclient.Client
	crdClient    apiextclient.Interface
)

// crdName is the installed CRD's object name, derived from the GVR so it follows
// the group version flip.
var crdName = migrationv1.DatastoreMigrationGVR.Resource + "." + migrationv1.Group

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

// run wraps setup, m.Run and teardown. TestMain can't do this itself because
// os.Exit skips deferred calls, which would orphan the envtest apiserver and its
// etcd whenever setup failed part way through.
func run(m *testing.M) int {
	repoRoot := libtestutils.FindRepoRoot()
	crdPath := filepath.Join(repoRoot, "kube-controllers", "pkg", "apis", "migration", "v1", "crd")

	testEnv, err := testutils.NewTestEnv(crdPath)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := testEnv.Stop(); err != nil {
			panic(err)
		}
	}()

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
	crdClient, err = apiextclient.NewForConfig(testEnv.RestConfig)
	if err != nil {
		panic(err)
	}
	return m.Run()
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

// TestSpecTypeIsImmutable checks that spec.type carries a transition rule pinning
// it to the value it was created with. The migration is a one-shot operation;
// switching type mid-flight has no coherent meaning.
//
// The immutability assertion is structural, against the CRD schema, and that is
// deliberate. Do not "strengthen" it into an assertion about the rejection the
// apiserver returns for a changed spec.type, because no such assertion is
// possible. spec.type is enum constrained to a single value, so any changed value
// trips the enum, and an enum violation is a blocking error: see hasBlockingErr in
// apiextensions-apiserver's customresource strategy, which skips CEL validation
// entirely and appends a placeholder error on field "<nil>" in its place. Scoping
// the rule up to spec doesn't help, since hasBlockingErr scans the whole error
// list.
//
// The rule is latent for the same reason. On a single member enum self == oldSelf
// can never fire in production. It goes live the day a second migration type is
// added, which is exactly when it starts to matter.
func TestSpecTypeIsImmutable(t *testing.T) {
	ctx := context.Background()
	m := newMigration("immutable-type")
	if err := schemaClient.Create(ctx, m); err != nil {
		t.Fatalf("create with a valid type should be accepted: %v", err)
	}
	defer func() { _ = schemaClient.Delete(ctx, m) }()

	// Smoke check only: a changed type must not slip through, whichever rule
	// catches it.
	m.Spec.Type = migrationv1.DatastoreMigrationType("SomethingElse")
	if err := schemaClient.Update(ctx, m); err == nil {
		t.Error("expected a changed spec.type to be rejected")
	}

	crd, err := crdClient.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crdName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get crd %q: %v", crdName, err)
	}
	for _, version := range crd.Spec.Versions {
		if !version.Served {
			continue
		}
		if !specTypeHasTransitionRule(version) {
			t.Errorf("version %q carries no transition rule referencing oldSelf on spec.type", version.Name)
		}
	}
}

// specTypeHasTransitionRule reports whether version puts a CEL rule referencing
// oldSelf on spec.type. Matching on oldSelf rather than on the whole expression
// keeps this independent of how the rule ends up being spelled.
func specTypeHasTransitionRule(version apiextv1.CustomResourceDefinitionVersion) bool {
	if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
		return false
	}

	spec, ok := version.Schema.OpenAPIV3Schema.Properties["spec"]
	if !ok {
		return false
	}
	specType, ok := spec.Properties["type"]
	if !ok {
		return false
	}
	for _, rule := range specType.XValidations {
		if strings.Contains(rule.Rule, "oldSelf") {
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

	// Fatal rather than Errorf on purpose. Status().Update writes the server
	// response back into m, so carrying on past a failure here would leave a stale
	// resourceVersion and turn the rejection check below into a Conflict.
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
			t.Fatalf("phase %q should be accepted: %v", phase, err)
		}
	}

	m.Status.Phase = migrationv1.DatastoreMigrationPhase("Bogus")
	err := schemaClient.Status().Update(ctx, m)
	if err == nil {
		t.Fatal("expected an out-of-enum phase to be rejected")
	}
	if !hasCause(err, "status.phase", metav1.CauseTypeFieldValueNotSupported) {
		t.Fatalf("expected the enum to reject status.phase, got: %v", err)
	}
}

// hasCause reports whether err is an API status error carrying a validation cause
// of causeType on field. Asserting on the cause rather than on "an error came
// back" stops an unrelated rejection, a Conflict for instance, from satisfying the
// caller, and keeps clear of the rule's message text.
func hasCause(err error, field string, causeType metav1.CauseType) bool {
	var statusErr kerrors.APIStatus
	if !errors.As(err, &statusErr) {
		return false
	}

	details := statusErr.Status().Details
	if details == nil {
		return false
	}
	for _, cause := range details.Causes {
		if cause.Field == field && cause.Type == causeType {
			return true
		}
	}
	return false
}

// TestConditionsMergeByType checks that two writers touching different conditions
// don't clobber each other. Without listType=map on the conditions list,
// server-side apply treats it as atomic and the second writer wins outright.
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
		return applyStatus(ctx, t, fieldOwner, patch)
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

	// Check identity, not just how many survived. The message records which writer
	// set each condition, so a survivor carrying the wrong message means one apply
	// overwrote the other's entry in place rather than merging alongside it.
	for _, expected := range []struct {
		condType string
		message  string
	}{
		{
			condType: "Conflicted",
			message:  "set by writer-a",
		},
		{
			condType: "Degraded",
			message:  "set by writer-b",
		},
	} {
		cond := apimeta.FindStatusCondition(got.Status.Conditions, expected.condType)
		if cond == nil {
			t.Errorf("condition %q did not survive, conditions are %+v", expected.condType, got.Status.Conditions)
			continue
		}
		if cond.Message != expected.message {
			t.Errorf("condition %q has message %q, want %q", expected.condType, cond.Message, expected.message)
		}
	}

	// Per-entry ownership is the thing listType=map actually buys. With a map each
	// applier owns the entry keyed by its own condition type; with an atomic list
	// there are no per-entry keys to own, so writer-b's forced apply takes the whole
	// field and writer-a's entry goes away.
	if !ownsListEntry(t, got.ManagedFields, "writer-a", []string{"f:status", "f:conditions"}, fmt.Sprintf(`k:{"type":%q}`, "Conflicted")) {
		t.Errorf("expected writer-a to still own the Conflicted condition, managed fields are %+v", got.ManagedFields)
	}
}

// TestTypeDetailsMergeByKind is TestConditionsMergeByType for the other status
// list. status.progress.typeDetails is keyed on kind rather than type, and getting
// the key wrong is the easy mistake, so it gets its own check.
func TestTypeDetailsMergeByKind(t *testing.T) {
	ctx := context.Background()
	m := newMigration("type-details-merge")
	if err := schemaClient.Create(ctx, m); err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = schemaClient.Delete(ctx, m) }()

	applyTypeDetail := func(fieldOwner, kind string, migrated int32) error {
		patch := &migrationv1.DatastoreMigration{
			TypeMeta: metav1.TypeMeta{
				Kind:       "DatastoreMigration",
				APIVersion: migrationv1.SchemeGroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{Name: m.Name},
			Status: migrationv1.DatastoreMigrationStatus{
				Progress: migrationv1.DatastoreMigrationProgress{
					TypeDetails: []migrationv1.TypeMigrationProgress{{
						Kind:     kind,
						Migrated: migrated,
					}},
				},
			},
		}
		return applyStatus(ctx, t, fieldOwner, patch)
	}

	if err := applyTypeDetail("writer-a", "NetworkPolicy", 1); err != nil {
		t.Fatalf("writer-a apply: %v", err)
	}
	if err := applyTypeDetail("writer-b", "GlobalNetworkPolicy", 2); err != nil {
		t.Fatalf("writer-b apply: %v", err)
	}

	got := &migrationv1.DatastoreMigration{}
	if err := schemaClient.Get(ctx, ctrlclient.ObjectKey{Name: m.Name}, got); err != nil {
		t.Fatalf("get: %v", err)
	}

	// The migrated count identifies which writer set each entry, so a survivor
	// carrying the wrong count means one apply overwrote the other in place.
	for _, expected := range []struct {
		kind     string
		migrated int32
	}{
		{
			kind:     "NetworkPolicy",
			migrated: 1,
		},
		{
			kind:     "GlobalNetworkPolicy",
			migrated: 2,
		},
	} {
		detail := findTypeDetail(got.Status.Progress.TypeDetails, expected.kind)
		if detail == nil {
			t.Errorf("type detail %q did not survive, type details are %+v", expected.kind, got.Status.Progress.TypeDetails)
			continue
		}
		if detail.Migrated != expected.migrated {
			t.Errorf("type detail %q has migrated %d, want %d", expected.kind, detail.Migrated, expected.migrated)
		}
	}

	if !ownsListEntry(t, got.ManagedFields, "writer-a", []string{"f:status", "f:progress", "f:typeDetails"}, fmt.Sprintf(`k:{"kind":%q}`, "NetworkPolicy")) {
		t.Errorf("expected writer-a to still own the NetworkPolicy type detail, managed fields are %+v", got.ManagedFields)
	}
}

// findTypeDetail returns the entry for kind, or nil.
func findTypeDetail(details []migrationv1.TypeMigrationProgress, kind string) *migrationv1.TypeMigrationProgress {
	for i := range details {
		if details[i].Kind == kind {
			return &details[i]
		}
	}
	return nil
}

// TestStatusBoundsAreEnforced checks the MaxItems and MaxLength bounds on status.
// They keep an unbounded controller loop from growing the object without limit,
// and v1 is the last chance to tighten them.
func TestStatusBoundsAreEnforced(t *testing.T) {
	ctx := context.Background()
	m := newMigration("status-bounds")
	if err := schemaClient.Create(ctx, m); err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = schemaClient.Delete(ctx, m) }()

	for _, tc := range []struct {
		name      string
		overrun   func(status *migrationv1.DatastoreMigrationStatus)
		field     string
		causeType metav1.CauseType
	}{
		{
			name: "message past MaxLength",
			overrun: func(status *migrationv1.DatastoreMigrationStatus) {
				status.Message = strings.Repeat("m", 1025)
			},
			field:     "status.message",
			causeType: metav1.CauseTypeTooLong,
		},
		{
			name: "conditions past MaxItems",
			overrun: func(status *migrationv1.DatastoreMigrationStatus) {
				now := metav1.Now()
				for i := range 17 {
					status.Conditions = append(status.Conditions, metav1.Condition{
						Type:               fmt.Sprintf("Condition%d", i),
						Status:             metav1.ConditionTrue,
						Reason:             "Testing",
						LastTransitionTime: now,
					})
				}
			},
			field:     "status.conditions",
			causeType: metav1.CauseTypeTooMany,
		},
		{
			name: "typeDetails past MaxItems",
			overrun: func(status *migrationv1.DatastoreMigrationStatus) {
				for i := range 129 {
					status.Progress.TypeDetails = append(status.Progress.TypeDetails, migrationv1.TypeMigrationProgress{
						Kind: fmt.Sprintf("Kind%d", i),
					})
				}
			},
			field:     "status.progress.typeDetails",
			causeType: metav1.CauseTypeTooMany,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Fetch fresh each time so a rejected update from a previous case can't
			// leave a stale resourceVersion behind.
			got := &migrationv1.DatastoreMigration{}
			if err := schemaClient.Get(ctx, ctrlclient.ObjectKey{Name: m.Name}, got); err != nil {
				t.Fatalf("get: %v", err)
			}

			tc.overrun(&got.Status)
			err := schemaClient.Status().Update(ctx, got)
			if err == nil {
				t.Fatalf("expected the update to be rejected")
			}
			if !hasCause(err, tc.field, tc.causeType) {
				t.Fatalf("expected a %s cause on %s, got: %v", tc.causeType, tc.field, err)
			}
		})
	}
}

// applyStatus server-side applies patch's status subresource as fieldOwner. The
// typed object gets routed through unstructured because there are no generated
// apply configurations for DatastoreMigration.
func applyStatus(ctx context.Context, t *testing.T, fieldOwner string, patch *migrationv1.DatastoreMigration) error {
	t.Helper()

	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(patch)
	if err != nil {
		t.Fatalf("convert patch to unstructured: %v", err)
	}

	// The converter emits a null creationTimestamp from the empty ObjectMeta, and a
	// null in an apply configuration means "clear this field", which the apiserver
	// rejects on a field it manages itself.
	if metadata, ok := raw["metadata"].(map[string]any); ok {
		delete(metadata, "creationTimestamp")
	}
	return schemaClient.Status().Apply(
		ctx,
		ctrlclient.ApplyConfigurationFromUnstructured(&unstructured.Unstructured{Object: raw}),
		ctrlclient.FieldOwner(fieldOwner),
		ctrlclient.ForceOwnership,
	)
}

// ownsListEntry reports whether manager holds a managed fields entry owning the
// list entry at key, reached by walking path through its field set. The field set
// gets decoded rather than string matched, because the key is itself JSON and so
// comes back with its quotes escaped in the raw bytes.
func ownsListEntry(t *testing.T, entries []metav1.ManagedFieldsEntry, manager string, path []string, key string) bool {
	t.Helper()

	for _, entry := range entries {
		if entry.Manager != manager || entry.FieldsV1 == nil {
			continue
		}

		var fields map[string]any
		if err := json.Unmarshal(entry.FieldsV1.GetRawBytes(), &fields); err != nil {
			t.Fatalf("decode managed fields for %q: %v", manager, err)
		}
		cursor := fields
		for _, step := range path {
			next, ok := cursor[step].(map[string]any)
			if !ok {
				cursor = nil
				break
			}
			cursor = next
		}
		if cursor == nil {
			continue
		}
		if _, ok := cursor[key]; ok {
			return true
		}
	}
	return false
}
