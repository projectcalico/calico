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

package externalnode

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onsi/gomega"
)

const testsDir = "../../tests"

// The ssh probe returns no addresses when the external node is unreachable, and
// indexing that empty slice used to panic and take the whole Ginkgo node down.
func TestIPWithNoDiscoveredAddressesFails(t *testing.T) {
	gomega.RegisterTestingT(t)
	c := &Client{extIP: "10.0.0.1", intIPs: []string{}}

	err := gomega.InterceptGomegaFailure(func() {
		c.IP()
	})
	if err == nil {
		t.Fatal("expected IP() to fail when no internal IPs were discovered")
	}
	if !strings.Contains(err.Error(), "10.0.0.1") {
		t.Errorf("failure message should name the external node, got: %s", err.Error())
	}
}

func TestIPReturnsFirstDiscoveredAddress(t *testing.T) {
	gomega.RegisterTestingT(t)
	c := &Client{extIP: "10.0.0.1", intIPs: []string{"172.16.0.5", "172.16.0.6"}}

	err := gomega.InterceptGomegaFailure(func() {
		if got := c.IP(); got != "172.16.0.5" {
			t.Errorf("IP() = %s, want 172.16.0.5", got)
		}
	})
	if err != nil {
		t.Fatalf("unexpected failure: %s", err)
	}
}

// NewClient returns nil on a cluster with no external node, leaving each caller to
// decide what that means. MustNewClient fails with the label a lane should exclude.
func TestTestsUseMustNewClient(t *testing.T) {
	for _, path := range testFilesCalling(t, "externalnode.NewClient") {
		t.Errorf("%s: use externalnode.MustNewClient instead of NewClient", path)
	}
}

// A test that needs the external node without the label runs on every lane,
// including the ones whose clusters have no external node.
func TestTestsNeedingTheExternalNodeCarryTheLabel(t *testing.T) {
	paths := testFilesCalling(t, "externalnode.MustNewClient")
	if len(paths) == 0 {
		t.Fatal("no e2e test calls externalnode.MustNewClient, so this guard checks nothing")
	}
	for _, path := range paths {
		if !fileContains(t, path, "ExternalNode") {
			t.Errorf("%s: needs the external node but carries no describe.WithExternalNode label", path)
		}
	}
}

// testFilesCalling returns the e2e test files that call the named function.
func testFilesCalling(t *testing.T, fn string) []string {
	t.Helper()

	var paths []string
	err := filepath.WalkDir(testsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if fileContains(t, path, fn+"(") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", testsDir, err)
	}
	return paths
}

func fileContains(t *testing.T, path, s string) bool {
	t.Helper()

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return strings.Contains(string(contents), s)
}
