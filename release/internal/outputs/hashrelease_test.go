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

package outputs

import (
	"os"
	"path/filepath"
	"testing"

	approvals "github.com/approvals/go-approval-tests"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/slack"
)

func TestPublishedHashrelease(t *testing.T) {
	t.Parallel()

	t.Run("no slack response", func(t *testing.T) {
		t.Parallel()
		td := t.TempDir()
		h := &PublishedHashrelease{Hashrelease: &hashreleaseserver.Hashrelease{
			Name:            "2026-01-06-v3-32-vertigo",
			Hash:            "v3.32.0-0.dev-527-g92e0cd84e375-v1.42.0-0.dev-16-g3a924017cc9f",
			Stream:          "master",
			ProductVersion:  "v3.32.0-0.dev-527-g92e0cd84e375",
			OperatorVersion: "v1.42.0-0.dev-16-g3a924017cc9f",
		}}

		gotPath, err := h.Write(td)
		if err != nil {
			t.Fatalf("Write() returned error: %v", err)
		}
		expected := filepath.Join(td, hashreleaseOutputFileName)
		if gotPath != expected {
			t.Fatalf("unexpected path: got %q want %q", gotPath, expected)
		}

		content, err := os.ReadFile(gotPath)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}
		approvals.VerifyString(t, string(content))
	})

	t.Run("with slack response", func(t *testing.T) {
		t.Parallel()
		td := t.TempDir()
		h := &PublishedHashrelease{
			Hashrelease: &hashreleaseserver.Hashrelease{
				Name:            "2026-01-06-v3-32-vertigo",
				Hash:            "v3.32.0-0.dev-527-g92e0cd84e375-v1.42.0-0.dev-16-g3a924017cc9f",
				Stream:          "master",
				ProductVersion:  "v3.32.0-0.dev-527-g92e0cd84e375",
				OperatorVersion: "v1.42.0-0.dev-16-g3a924017cc9f",
			},
			SlackResponse: &slack.MessageResponse{
				Channel:   "C123ABC456",
				Timestamp: "1503435956.000247",
			},
		}

		gotPath, err := h.Write(td)
		if err != nil {
			t.Fatalf("Write() returned error: %v", err)
		}
		expected := filepath.Join(td, hashreleaseOutputFileName)
		if gotPath != expected {
			t.Fatalf("unexpected path: got %q want %q", gotPath, expected)
		}

		content, err := os.ReadFile(gotPath)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}
		approvals.VerifyString(t, string(content))
	})
}
