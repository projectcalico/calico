// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// format-go-file applies the project's canonical 3-step formatting pipeline
// (goimports / coalesce-imports / goimports) to one or more Go files. It is
// intended to be cheap enough to run on every editor save or on every
// Claude Code Edit/Write tool call.
//
// Usage:
//
//	go run ./hack/cmd/format-go-file <path>...
//	go run ./hack/cmd/format-go-file --claude-hook < <hook-event-json>
//
// Paths may be absolute, repo-relative, or $PWD-relative. Paths that are
// not Go files, that live under vendor/ or third_party/, that don't exist,
// or that fall outside the repo are silently skipped, so callers (editor
// hooks, Claude PostToolUse hooks) can pass any file path without
// pre-filtering.
//
// With --claude-hook, the program reads the Claude Code PostToolUse JSON
// event on stdin and pulls tool_input.file_path out of it. This avoids
// depending on jq in the hook command itself.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const localImportPrefix = "github.com/projectcalico/calico/"

var claudeHook = flag.Bool("claude-hook", false,
	"Read a Claude Code PostToolUse JSON event on stdin and use its tool_input.file_path.")

func main() {
	flag.Parse()

	paths := flag.Args()
	if *claudeHook {
		p, err := pathFromClaudeHook(os.Stdin)
		if err != nil {
			// Malformed input: not fatal — silently no-op so a stray
			// invocation can never block an edit.
			return
		}
		if p == "" {
			return
		}
		paths = append(paths, p)
	}

	if len(paths) == 0 {
		return
	}

	repoDir, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "format-go-file: %v\n", err)
		os.Exit(1)
	}

	relPaths := filterAndRelativize(paths, repoDir)
	if len(relPaths) == 0 {
		return
	}

	if err := formatFiles(repoDir, relPaths); err != nil {
		fmt.Fprintf(os.Stderr, "format-go-file: %v\n", err)
		os.Exit(1)
	}
}

type hookEvent struct {
	ToolInput struct {
		// Edit / Write / MultiEdit all carry file_path on tool_input.
		FilePath string `json:"file_path"`
	} `json:"tool_input"`
}

func pathFromClaudeHook(r *os.File) (string, error) {
	var ev hookEvent
	if err := json.NewDecoder(r).Decode(&ev); err != nil {
		return "", err
	}
	return ev.ToolInput.FilePath, nil
}

// findRepoRoot walks up from $CLAUDE_PROJECT_DIR (if set) or the current
// directory until it finds a go.mod, and returns that directory. The
// containing repo has a go.mod at the root so this is unambiguous.
func findRepoRoot() (string, error) {
	start := os.Getenv("CLAUDE_PROJECT_DIR")
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("getwd: %w", err)
		}
	}
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", start)
		}
		dir = parent
	}
}

// filterAndRelativize resolves each input path to an absolute path, drops
// anything that is not a .go file inside the repo, and returns the
// surviving paths as repo-root-relative paths.
func filterAndRelativize(paths []string, repoDir string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		abs, err := resolveExistingFile(p, repoDir)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(repoDir, abs)
		if err != nil || rel == "" {
			continue
		}
		// filepath.Rel can return e.g. "../foo" for paths outside the
		// repo. Reject those.
		if rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
			continue
		}
		if filepath.Ext(rel) != ".go" {
			continue
		}
		// Skip vendored / third_party trees.
		first := firstPathSegment(rel)
		if first == "vendor" || first == "third_party" {
			continue
		}
		out = append(out, rel)
	}
	return out
}

// resolveExistingFile picks the first interpretation of p that names an
// existing regular file: as-given (relative to $PWD or already absolute),
// then relative to the repo root.
func resolveExistingFile(p, repoDir string) (string, error) {
	candidates := []string{p}
	if !filepath.IsAbs(p) {
		candidates = append(candidates, filepath.Join(repoDir, p))
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		fi, err := os.Stat(abs)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		return abs, nil
	}
	return "", fmt.Errorf("not found: %s", p)
}

func firstPathSegment(rel string) string {
	for i := 0; i < len(rel); i++ {
		if rel[i] == filepath.Separator {
			return rel[:i]
		}
	}
	return rel
}

// formatFiles runs the canonical 3-step pipeline against the given
// repo-root-relative paths.
func formatFiles(repoDir string, relPaths []string) error {
	steps := []struct {
		name string
		args []string
	}{
		{"goimports (coalesce)", append([]string{"tool", "goimports", "-w", "-local", localImportPrefix}, relPaths...)},
		{"coalesce-imports", append([]string{"run", "./hack/cmd/coalesce-imports", "-w"}, relPaths...)},
		{"goimports (whitespace)", append([]string{"tool", "goimports", "-w", "-local", localImportPrefix}, relPaths...)},
	}
	for _, s := range steps {
		cmd := exec.Command("go", s.args...)
		cmd.Dir = repoDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}
