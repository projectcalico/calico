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

package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

// Replace maps to ActionUpdate, which reports failures in results.Err rather
// than results.ResErrs, and ExecuteConfigCommand still counts the resource
// (NumHandled) even when the update errors. reportReplaceResults must key off
// results.Err, otherwise a stale resource-version conflict is reported as
// success.
func TestReportReplaceResults(t *testing.T) {
	conflict := errors.New("update conflict: the resource version does not match")

	for _, tc := range []struct {
		name      string
		results   common.CommandResults
		wantErr   bool
		wantInErr string
	}{
		{
			name:      "conflict on single resource still counted as handled",
			results:   common.CommandResults{NumResources: 1, NumHandled: 1, SingleKind: "NetworkPolicy", Err: conflict},
			wantErr:   true,
			wantInErr: "update conflict",
		},
		{
			name:    "successful replace",
			results: common.CommandResults{NumResources: 1, NumHandled: 1, SingleKind: "NetworkPolicy"},
			wantErr: false,
		},
		{
			name:      "nothing handled returns the underlying error",
			results:   common.CommandResults{NumResources: 1, NumHandled: 0, SingleKind: "NetworkPolicy", Err: conflict},
			wantErr:   true,
			wantInErr: "update conflict",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := reportReplaceResults(&tc.results)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantInErr != "" && !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q should contain %q", err, tc.wantInErr)
			}
		})
	}
}

// TestValidateCommand drives the command tree rather than calling the
// validator directly, so it covers the wiring that turns CRD validation on for
// an offline validate.
func TestValidateCommand(t *testing.T) {
	for _, tc := range []struct {
		name      string
		manifest  string
		wantInErr string
	}{
		{
			name: "duplicate networkSet address is rejected",
			manifest: `apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: dup
  namespace: default
spec:
  nets:
  - 10.0.0.1/32
  - 10.0.0.1/32
`,
			wantInErr: `Duplicate value: "10.0.0.1/32"`,
		},
		{
			name: "distinct networkSet addresses are accepted",
			manifest: `apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: distinct
  namespace: default
spec:
  nets:
  - 10.0.0.1/32
  - 10.0.0.2/32
`,
		},
		{
			name: "policy failing a CEL rule is rejected",
			manifest: `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: bad-icmp
spec:
  selector: all()
  ingress:
  - action: Allow
    protocol: ICMP
    icmp:
      code: 1
`,
			wantInErr: "ICMP code specified without an ICMP type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The registry is process-wide, so clear it first to prove the
			// command is what enables CRD validation.
			validator.SetCRDValidationEnabled(false)
			t.Cleanup(func() {
				validator.SetCRDValidationEnabled(false)
			})

			path := filepath.Join(t.TempDir(), "resource.yaml")
			if err := os.WriteFile(path, []byte(tc.manifest), 0o644); err != nil {
				t.Fatalf("failed to write manifest: %v", err)
			}

			cmd := NewCommand()
			cmd.SetArgs([]string{"validate", "-f", path})
			err := cmd.Execute()

			if tc.wantInErr == "" {
				if err != nil {
					t.Fatalf("expected the resource to validate, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q should contain %q", err, tc.wantInErr)
			}
		})
	}
}
