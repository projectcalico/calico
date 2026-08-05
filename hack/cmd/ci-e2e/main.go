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

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

func main() {
	var (
		prFlag          = flag.String("pr", "", "PR number (auto-detected from current branch if omitted)")
		profileFlag     = flag.String("profile", "", "Test profile (interactive menu if omitted)")
		labelFilterFlag = flag.String("label-filter", "", "Ginkgo label-filter expression")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: go run ./hack/cmd/ci-e2e [flags]

Triggers e2e tests on a pull request by posting a /e2e comment.

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  go run ./hack/cmd/ci-e2e --profile=bpf-gcp --label-filter="Feature:BPF" --pr=12345
  make ci-e2e PROFILE=bpf-gcp LABEL_FILTER="Feature:BPF"
  make ci-e2e   # fully interactive
`)
	}
	flag.Parse()

	repoRoot := findRepoRoot()
	profilesPath := filepath.Join(repoRoot, ".github", "e2e-profiles.yaml")
	pathLabelsPath := filepath.Join(repoRoot, ".github", "e2e-path-labels.yaml")

	requireCommand("gh")

	profiles, err := loadProfiles(profilesPath)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load profiles")
	}

	pr := *prFlag
	if pr == "" {
		pr = detectPR()
	}

	profile := *profileFlag
	if profile == "" {
		profile = promptProfile(profiles)
	} else {
		if _, err := validateProfile(profiles, profile); err != nil {
			logrus.Fatal(err)
		}
	}

	// Suggest labels from changed files.
	suggestedLabel, suggestedReason := suggestFromPR(pathLabelsPath, profile, pr)
	if suggestedLabel != "" && suggestedReason != "" {
		fmt.Printf("\nChanged files suggest: %s (%s)\n", suggestedLabel, suggestedReason)
	}

	labelFilter := *labelFilterFlag
	if labelFilter == "" {
		labelFilter = promptLabelFilter(suggestedLabel)
	}

	cmd := buildCommand(profile, labelFilter)
	fmt.Printf("\nTriggering: %s on PR #%s\n", cmd, pr)

	if !isInteractive() || (*profileFlag != "" && *prFlag != "" && *labelFilterFlag != "") {
		// Non-interactive or all flags provided - skip confirmation.
	} else {
		if !confirm("Continue?") {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
	}

	postComment(pr, cmd)
	fmt.Printf("\nTriggered. Watch progress on PR #%s.\n", pr)
}

// findRepoRoot walks up from the current working directory looking for go.mod.
func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get working directory")
	}
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	logrus.Fatal("Could not find repo root (no go.mod found)")
	return ""
}

func requireCommand(name string) {
	if _, err := exec.LookPath(name); err != nil {
		logrus.Fatalf("%q is required but not found in PATH", name)
	}
}

type prInfo struct {
	Number      int    `json:"number"`
	HeadRefName string `json:"headRefName"`
}

func detectPR() string {
	out, err := exec.Command("gh", "pr", "view", "--json", "number,headRefName").Output()
	if err != nil {
		logrus.Fatal("Could not detect a PR for the current branch. Use --pr=NUM to specify one.")
	}
	var info prInfo
	if err := json.Unmarshal(out, &info); err != nil {
		logrus.WithError(err).Fatal("Failed to parse PR info")
	}
	fmt.Printf("Detected PR #%d (%s)\n", info.Number, info.HeadRefName)
	return strconv.Itoa(info.Number)
}

func promptProfile(profiles map[string]Profile) string {
	keys := sortedProfileKeys(profiles)
	fmt.Println("\nSelect profile:")
	for i, k := range keys {
		fmt.Printf("  %d) %-20s - %s\n", i+1, k, profiles[k].Description)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			logrus.Fatal("No input received")
		}
		input := strings.TrimSpace(scanner.Text())

		// Accept a number.
		if n, err := strconv.Atoi(input); err == nil && n >= 1 && n <= len(keys) {
			return keys[n-1]
		}

		// Accept a name directly.
		if _, ok := profiles[input]; ok {
			return input
		}

		fmt.Printf("Invalid selection. Enter a number (1-%d) or a profile name.\n", len(keys))
	}
}

func suggestFromPR(pathLabelsPath, profile, pr string) (string, string) {
	rules, err := loadPathLabels(pathLabelsPath)
	if err != nil {
		return "", ""
	}

	out, err := exec.Command("gh", "pr", "diff", pr, "--name-only").Output()
	if err != nil {
		return "", ""
	}

	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.TrimSpace(line); f != "" {
			files = append(files, f)
		}
	}

	return suggestLabels(rules, profile, files)
}

func promptLabelFilter(suggested string) string {
	if !isInteractive() {
		return suggested
	}

	fmt.Println()
	if suggested != "" {
		fmt.Printf("Label filter [%s]:\n> ", suggested)
	} else {
		fmt.Print("Label filter (leave blank to run all tests):\n> ")
	}

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return suggested
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" {
		return suggested
	}
	return input
}

func buildCommand(profile, labelFilter string) string {
	cmd := "/e2e " + profile
	if labelFilter != "" {
		cmd += fmt.Sprintf(` --label-filter="%s"`, labelFilter)
	}
	return cmd
}

func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func confirm(prompt string) bool {
	fmt.Printf("%s [Y/n] ", prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false
	}
	input := strings.TrimSpace(scanner.Text())
	return input == "" || strings.EqualFold(input, "y")
}

func postComment(pr, body string) {
	cmd := exec.Command("gh", "pr", "comment", pr, "--body", body)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logrus.WithError(err).Fatal("Failed to post comment")
	}
}
