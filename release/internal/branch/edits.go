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

package branch

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/sirupsen/logrus"
)

// Edit is one reference replacement. A missing file or unmatched pattern is
// skipped unless Required, when it fails the cut.
type Edit struct {
	File        string
	Pattern     string
	Replacement string
	Required    bool
}

// editState classifies one edit against the current tree.
type editState int

const (
	editDone    editState = iota // Replacement already present
	editPending                  // Pattern matches; a write is needed
	editSkip                     // file missing or Pattern absent (and not done)
)

// editClassification carries an edit's state plus, for editPending, the compiled
// pattern and content so the caller writes without re-reading.
type editClassification struct {
	state   editState
	reason  string
	re      *regexp.Regexp
	content []byte
}

// classify reports an edit's state against the current tree. A missing or
// absent-pattern edit that is Required returns an error.
func classify(repoRoot string, e Edit) (editClassification, error) {
	content, readErr := os.ReadFile(filepath.Join(repoRoot, e.File))
	if readErr != nil {
		if e.Required {
			return editClassification{}, fmt.Errorf("required edit target missing: %s (%w)", e.File, readErr)
		}
		return editClassification{state: editSkip, reason: fmt.Sprintf("%s (%v)", e.File, readErr)}, nil
	}
	re, reErr := regexp.Compile(`(?m)` + e.Pattern)
	if reErr != nil {
		return editClassification{}, fmt.Errorf("bad pattern for %s: %w", e.File, reErr)
	}
	if !re.Match(content) {
		if e.Required {
			return editClassification{}, fmt.Errorf("required edit pattern not found: %s (%q)", e.File, e.Pattern)
		}
		return editClassification{state: editSkip, reason: fmt.Sprintf("%s (pattern %q not found)", e.File, e.Pattern)}, nil
	}
	// Done when applying the replacement changes nothing. This handles a
	// Replacement with capture-group refs ($1), which never appears literally.
	if bytes.Equal(re.ReplaceAll(content, []byte(e.Replacement)), content) {
		return editClassification{state: editDone, content: content}, nil
	}
	return editClassification{state: editPending, re: re, content: content}, nil
}

// ApplyEdits writes pending edits and returns the files to stage. Already-applied
// edits are staged too: a resume may find them on disk but not yet committed.
func ApplyEdits(repoRoot string, edits []Edit) (written, skipped []string, err error) {
	seen := map[string]bool{}
	stage := func(file string) {
		if !seen[file] {
			seen[file] = true
			written = append(written, file)
		}
	}
	for _, e := range edits {
		c, cErr := classify(repoRoot, e)
		if cErr != nil {
			return written, skipped, fmt.Errorf("apply edits: %w", cErr)
		}
		switch c.state {
		case editDone:
			stage(e.File)
			continue
		case editSkip:
			logrus.WithField("edit", c.reason).Warn("apply-edits: skipping")
			skipped = append(skipped, c.reason)
			continue
		}
		updated := c.re.ReplaceAll(c.content, []byte(e.Replacement))
		if writeErr := os.WriteFile(filepath.Join(repoRoot, e.File), updated, 0o644); writeErr != nil {
			return written, skipped, fmt.Errorf("apply edits: writing %s: %w", e.File, writeErr)
		}
		stage(e.File)
	}
	return written, skipped, nil
}
