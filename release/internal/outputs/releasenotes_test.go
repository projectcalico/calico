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
	"reflect"
	"regexp"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/google/go-github/v53/github"
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
			ID:    456,
			Note:  "A test bug fix release note.",
			Repo:  "calico",
			URL:   "https://github.com/projectcalico/calico/pull/456",
			IsBug: true,
		},
		{
			ID:   789,
			Note: "Another test release note.",
			Repo: "calico",
			URL:  "https://github.com/projectcalico/calico/pull/789",
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

func TestExtractReleaseNoteFromIssue(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "single line",
			body: "```release-note\nFixed a thing.\n```",
			want: []string{"Fixed a thing."},
		},
		{
			name: "word-wrapped note is joined",
			body: "```release-note\nFixed a thing that\nwraps onto two lines.\n```",
			want: []string{"Fixed a thing that wraps onto two lines."},
		},
		{
			name: "bulleted notes with CRLF are split",
			body: "```release-note\r\n* First fix.\r\n* Second fix.\r\n- Third fix.\r\n+ Fourth fix.\r\n```\r\n",
			want: []string{"First fix.", "Second fix.", "Third fix.", "Fourth fix."},
		},
		{
			name: "wrapped bullet continuation is joined",
			body: "```release-note\n- First fix that\n  wraps.\n\n- Second fix.\n```",
			want: []string{"First fix that wraps.", "Second fix."},
		},
		{
			name: "multiple blocks",
			body: "```release-note\nOne.\n```\ntext\n```release-note\nTwo.\n```",
			want: []string{"One.", "Two."},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			got, err := extractReleaseNoteFromIssue(&github.Issue{Body: &body})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractReleaseNoteDetectsBugLabel(t *testing.T) {
	body := "```release-note\nFixed a thing.\n```"
	issues := []*github.Issue{
		{
			Number: github.Int(1),
			Body:   &body,
			Labels: []*github.Label{{Name: github.String(releaseNoteRequiredLabel)}, {Name: github.String(bugLabel)}},
		},
		{
			Number: github.Int(2),
			Body:   &body,
			Labels: []*github.Label{{Name: github.String(releaseNoteRequiredLabel)}},
		},
	}
	notes, err := extractReleaseNote("calico", issues)
	if err != nil {
		t.Fatalf("extractReleaseNote returned error: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("expected 2 notes, got %d", len(notes))
	}
	if !notes[0].IsBug {
		t.Errorf("expected issue 1 (labelled %s) to be a bug fix", bugLabel)
	}
	if notes[1].IsBug {
		t.Errorf("expected issue 2 (no %s label) not to be a bug fix", bugLabel)
	}
}
