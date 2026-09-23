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
	"strings"
	"testing"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
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
