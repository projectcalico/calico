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

// felix-fv-memo computes the cache keys that let CI skip Felix FV batches whose
// inputs match a batch that already passed.
//
// A lane's key hashes the content of every file its batches can execute: the
// Go files that `go list` says are compiled into the FV binaries, and a fixed
// list of non-Go inputs.  Felix's unit-test files are not compiled into any FV
// binary, so they drop out; the bpf-gpl programs are inputs only to the BPF
// lanes, and the non-BPF lanes run with those objects deleted so that a missed
// dependency fails rather than passing on a stale entry.
//
// Usage:
//
//	felix-fv-memo [-explain <class>] <felix module yaml>
//
// prints one "<FELIX_TEST_GROUP> <class> <lane key>" line per felix-fv matrix
// entry.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// keyVersion is mixed into every key; bump it when the meaning of a cached
// pass changes in a way the hashed files do not capture.
const keyVersion = "v1"

type class string

const (
	classBPF    class = "bpf"
	classNonBPF class = "nonbpf"
)

// inputs lists what one class of lane executes.
type inputs struct {
	// goRoots are compiled with their full dependency closure.  Test packages
	// contribute their _test.go files.
	goRoots []string
	// shallowGoRoots contribute only their own files, not their imports.
	shallowGoRoots []string
	// files are tracked paths (files or directories) outside the Go build.
	files []string
}

var nonBPFInputs = inputs{
	goRoots: []string{
		// Felix runs as the cmd/calico binary, via node's "felix" subcommand.
		"./felix/daemon",
		"github.com/projectcalico/calico/lib/logrusr",
		"github.com/projectcalico/calico/pkg/buildinfo",
		// Typha runs from the calico image as `component typha`.
		"./typha/cmd/typha",
		"./felix/fv",
		"./felix/fv/test-workload",
		"./felix/fv/test-connection",
		"./felix/fv/pktgen",
		"./felix/cmd/calico-bpf",
	},
	// cmd/calico links every component; its other subcommands never run in FV.
	shallowGoRoots: []string{
		"./cmd/calico",
		"./node/pkg/node",
	},
	files: []string{
		"go.mod",
		"go.sum",
		"metadata.mk",
		"lib.Makefile",
		"cmd/calico",
		"docker/calico",
		"felix/Makefile",
		"felix/docker-image",
		"felix/fv",
		"felix/bpf-apache",
		// The FV API server loads these CRDs.
		"api/config/crd",
		"libcalico-go/config/crd",
		"hack/test/certs",
		// The fleet that runs the batches.
		".argoci/modules/20-felix.yaml",
		".argoci/scripts/load-cached-images",
		".argoci/scripts/vm-fleet-setup.sh",
		".semaphore/collect-artifacts",
		".semaphore/scripts/load-felix-prereqs.sh",
		".semaphore/vms",
		"felix/.semaphore",
		"hack/cmd/felix-fv-memo",
	},
}

var bpfInputs = nonBPFInputs.with(inputs{
	// The BPF lanes also run a "ut" batch.
	goRoots: []string{"./felix/bpf/ut"},
	files:   []string{"felix/bpf-gpl"},
})

func (in inputs) with(extra inputs) inputs {
	return inputs{
		goRoots:        slices.Concat(in.goRoots, extra.goRoots),
		shallowGoRoots: slices.Concat(in.shallowGoRoots, extra.shallowGoRoots),
		files:          slices.Concat(in.files, extra.files),
	}
}

// goBuildConfigs are the build configurations the FV binaries are compiled
// under; each can select different files.
var goBuildConfigs = []struct {
	env   []string
	flags []string
}{
	{env: []string{"CGO_ENABLED=1"}},
	{env: []string{"CGO_ENABLED=1"}, flags: []string{"-race"}},
	{env: []string{"CGO_ENABLED=0"}},
}

func main() {
	explain := flag.String("explain", "", "print the hashed inputs of this class (bpf or nonbpf) to stderr")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: felix-fv-memo [-explain <class>] <felix module yaml>")
		os.Exit(2)
	}

	repoRoot, err := gitOutput("rev-parse", "--show-toplevel")
	if err != nil {
		fail(err)
	}
	repoRoot = strings.TrimSpace(repoRoot)

	lanes, err := readLanes(flag.Arg(0))
	if err != nil {
		fail(err)
	}

	classKeys := map[class]string{}
	for c, in := range map[class]inputs{classBPF: bpfInputs, classNonBPF: nonBPFInputs} {
		manifest, err := buildManifest(repoRoot, in)
		if err != nil {
			fail(fmt.Errorf("computing %s inputs: %w", c, err))
		}
		if string(c) == *explain {
			_, _ = os.Stderr.Write(manifest)
		}
		classKeys[c] = hashOf(keyVersion, os.Getenv("FELIX_FV_MEMO_SALT"), string(manifest))
	}

	for _, l := range lanes {
		fmt.Printf("%s %s %s\n", l.group, l.class, hashOf(classKeys[l.class], l.group))
	}
}

type lane struct {
	group string
	class class
}

// readLanes returns the felix-fv matrix entries, identified by their
// FELIX_TEST_GROUP.
func readLanes(modulePath string) ([]lane, error) {
	raw, err := os.ReadFile(modulePath)
	if err != nil {
		return nil, err
	}
	var module struct {
		Steps []struct {
			Name   string `json:"name"`
			Matrix []struct {
				Name string `json:"name"`
				Env  []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"env"`
			} `json:"matrix"`
		} `json:"steps"`
	}
	if err := yaml.Unmarshal(raw, &module); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", modulePath, err)
	}

	var lanes []lane
	seen := map[string]bool{}
	for _, step := range module.Steps {
		if step.Name != "felix-fv" {
			continue
		}
		for _, entry := range step.Matrix {
			var group string
			for _, e := range entry.Env {
				if e.Name == "FELIX_TEST_GROUP" {
					group = e.Value
				}
			}
			if group == "" {
				return nil, fmt.Errorf("felix-fv matrix entry %q has no FELIX_TEST_GROUP", entry.Name)
			}
			if seen[group] {
				return nil, fmt.Errorf("FELIX_TEST_GROUP %q names two felix-fv matrix entries", group)
			}
			seen[group] = true
			lanes = append(lanes, lane{group: group, class: classOf(group)})
		}
	}
	if len(lanes) == 0 {
		return nil, fmt.Errorf("no felix-fv matrix entries in %s", modulePath)
	}
	return lanes, nil
}

// classOf mirrors felix/.semaphore/fv-prologue, which runs a group in BPF mode
// if its name contains "bpf".
func classOf(group string) class {
	if strings.Contains(group, "bpf") {
		return classBPF
	}
	return classNonBPF
}

// buildManifest returns one sorted line per input: "<path> <sha256>" for a file
// in the repo, "<module>@<version>" for a dependency outside it.
func buildManifest(repoRoot string, in inputs) ([]byte, error) {
	files := map[string]bool{}
	modules := map[string]bool{}

	for _, cfg := range goBuildConfigs {
		args := slices.Concat([]string{"list", "-deps", "-test", "-json"}, cfg.flags, in.goRoots)
		pkgs, err := goList(repoRoot, cfg.env, args)
		if err != nil {
			return nil, err
		}
		args = slices.Concat([]string{"list", "-json"}, cfg.flags, in.shallowGoRoots)
		shallow, err := goList(repoRoot, cfg.env, args)
		if err != nil {
			return nil, err
		}
		for _, p := range slices.Concat(pkgs, shallow) {
			if err := addPackage(repoRoot, p, files, modules); err != nil {
				return nil, err
			}
		}
	}

	tracked, err := gitOutput(slices.Concat([]string{"-C", repoRoot, "ls-files", "--"}, in.files)...)
	if err != nil {
		return nil, err
	}
	for _, f := range strings.Fields(tracked) {
		files[f] = true
	}
	// A renamed input would otherwise silently leave the key.
	for _, f := range in.files {
		if !matchesAny(files, f) {
			return nil, fmt.Errorf("input %q matches no tracked file", f)
		}
	}

	var lines []string
	for f := range files {
		sum, err := fileSHA256(filepath.Join(repoRoot, f))
		if err != nil {
			return nil, err
		}
		lines = append(lines, f+" "+sum)
	}
	for m := range modules {
		lines = append(lines, m)
	}
	slices.Sort(lines)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

type goPackage struct {
	ImportPath string
	Dir        string
	Standard   bool
	Module     *struct {
		Path    string
		Version string
		Replace *struct {
			Path    string
			Version string
		}
	}
	GoFiles, CgoFiles, CFiles, CXXFiles, HFiles, SFiles, SysoFiles, EmbedFiles []string
	Error                                                                      *struct{ Err string }
}

func addPackage(repoRoot string, p goPackage, files, modules map[string]bool) error {
	if p.Error != nil {
		return fmt.Errorf("go list: %s: %s", p.ImportPath, p.Error.Err)
	}
	// The toolchain is pinned by metadata.mk, which is itself an input.
	if p.Standard {
		return nil
	}
	// The generated test main lives in the build cache, not the repo.
	if strings.HasSuffix(p.ImportPath, ".test") {
		return nil
	}
	rel, err := filepath.Rel(repoRoot, p.Dir)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, "../") {
		if p.Module == nil {
			return fmt.Errorf("package %s is outside the repo but has no module", p.ImportPath)
		}
		m := p.Module.Path + "@" + p.Module.Version
		if r := p.Module.Replace; r != nil {
			m += " => " + r.Path + "@" + r.Version
		}
		modules[m] = true
		return nil
	}
	for _, f := range slices.Concat(p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.HFiles, p.SFiles, p.SysoFiles, p.EmbedFiles) {
		files[filepath.ToSlash(filepath.Join(rel, f))] = true
	}
	return nil
}

func goList(dir string, env, args []string) ([]goPackage, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = slices.Concat(os.Environ(), []string{"GOOS=linux", "GOARCH=amd64"}, env)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	var pkgs []goPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p goPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			return pkgs, nil
		} else if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
}

func matchesAny(files map[string]bool, pathOrDir string) bool {
	if files[pathOrDir] {
		return true
	}
	for f := range files {
		if strings.HasPrefix(f, pathOrDir+"/") {
			return true
		}
	}
	return false
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// hashOf hashes its parts, separated so that ("ab", "c") and ("a", "bc")
// differ.
func hashOf(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = fmt.Fprintf(h, "%d:%s;", len(p), p)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func gitOutput(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "felix-fv-memo:", err)
	os.Exit(1)
}
