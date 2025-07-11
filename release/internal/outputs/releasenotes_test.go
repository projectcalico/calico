// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"regexp"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
)

func TestOutputReleaseNotes(t *testing.T) {
	outputFilePath := filepath.Join(t.TempDir(), "release-notes.md")
	if err := outputReleaseNotes([]*ReleaseNoteIssueData{
		{
			ID:   123,
			Note: "This is a test release note.",
			Repo: "calico",
			URL:  "https://github.com/projectcalico/calico/pull/123",
		},
		{
			ID:   456,
			Note: "Another test release note.",
			Repo: "calico",
			URL:  "https://github.com/projectcalico/calico/pull/456",
		},
	}, outputFilePath); err != nil {
		t.Fatalf("Failed to output release notes: %v", err)
	}
	relNotes, err := os.ReadFile(outputFilePath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}
	dateRegex := regexp.MustCompile(`\b\d{2} [A-Za-z]{3} \d{4}\b`)
	approvals.VerifyString(t, string(relNotes),
		approvals.Options().AddScrubber(approvals.CreateRegexScrubber(dateRegex, "[Date]")))
}
