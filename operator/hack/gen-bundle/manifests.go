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

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// The manifests and Calico CRDs the bundle ships were downloaded from the
// Calico repository back when the operator was a repository of its own. They are
// read from the working tree now that the operator builds out of Calico, so a
// bundle carries the manifests it was built alongside rather than whatever a
// pinned release published. Every path below is relative to the repository root
// that --repo-root names, so none of them depend on the directory gen-bundle
// happens to be run from.
const (
	// ocpManifestDir holds the OpenShift manifests. They are generated from
	// charts/ by 'make gen-manifests' at the repository root and committed.
	ocpManifestDir = "manifests"

	// calicoCRDDir holds the Calico CRDs, the same directory the operator embeds
	// them from at runtime - see the libcalico-go/config/crd import in pkg/crds.
	calicoCRDDir = "libcalico-go/config/crd"

	// operatorCRDDir holds the committed operator CRDs. 'make gen-files' and the
	// CI dirty-check keep them current, so the bundle ships them as they are.
	operatorCRDDir = "operator/pkg/crds/operator"
)

// calicoResources are the Calico CRDs the bundle ships. Keep this list, the
// owned CRDs in config/manifests/bases/tigera-operator.clusterserviceversion.yaml,
// and the internal-objects annotation in that same file in sync: a CRD listed
// here but not described there generates a bundle-validation warning, and a CRD
// described there but not listed here is advertised by the CSV without being
// installed.
var calicoResources = []string{
	"bgpconfigurations",
	"bgppeers",
	"blockaffinities",
	"caliconodestatuses",
	"clusterinformations",
	"felixconfigurations",
	"globalnetworkpolicies",
	"globalnetworksets",
	"hostendpoints",
	"ipamblocks",
	"ipamconfigs",
	"ipamhandles",
	"ippools",
	"ipreservations",
	"kubecontrollersconfigurations",
	"networkpolicies",
	"networksets",
}

// operatorCRDs are the operator CRDs the bundle ships, relative to the
// committed CRD directory.
var operatorCRDs = []string{
	"operator.tigera.io_installations.yaml",
	"operator.tigera.io_tigerastatuses.yaml",
	"operator.tigera.io_imagesets.yaml",
}

// sampleCRs become the CSV's alm-examples annotation, which is what OperatorHub
// offers users as a starting point in its "Create instance" forms. Only kinds
// whose CRD the bundle ships belong here - an example for a kind the CSV does
// not own is dropped, and every owned CRD without an example is reported by
// 'operator-sdk bundle validate'. Each entry is the canonical copy of that
// example: the Installation one is the OpenShift install-time CR itself, so
// that what OperatorHub offers and what the OpenShift install instructions
// tell users to apply cannot drift apart.
var sampleCRs = []string{
	ocpManifestDir + "/ocp/03-cr-installation.yaml",
	"operator/config/samples/operator_v1_imageset.yaml",
}

var getManifestsCommand = &cli.Command{
	Name:  "get-manifests",
	Usage: "Stage the Calico and operator manifests that 'operator-sdk generate bundle' reads to build a ClusterServiceVersion",
	Flags: []cli.Flag{repoRootFlag, crdDirFlag, deployDirFlag},
	Action: func(_ context.Context, c *cli.Command) error {
		return getManifests(c.String(repoRootFlag.Name), c.String(crdDirFlag.Name), c.String(deployDirFlag.Name))
	},
}

func getManifests(repoRoot, crdDir, deployDir string) error {
	// Start from empty staging directories. Leftovers from an earlier run would
	// otherwise be picked up by operator-sdk and end up in the bundle - for
	// example a CRD that has since been dropped from calicoResources.
	for _, dir := range []string{crdDir, deployDir} {
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("clearing %s: %w", dir, err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}

	logrus.Infof("Building bundle from %s, with the manifests in %s", deployDir, repoRoot)

	if err := copyOperatorManifests(repoRoot, deployDir); err != nil {
		return err
	}
	if err := copySampleCRs(repoRoot, deployDir); err != nil {
		return err
	}
	if err := copyOperatorCRDs(repoRoot, crdDir); err != nil {
		return err
	}
	return copyCalicoCRDs(repoRoot, crdDir)
}

// copyOperatorManifests stages the OpenShift manifests that the CSV's install
// spec is built from. For CSV generation we use a version of the operator
// deployment manifest that doesn't include an init container and volumes for
// creating install-time resources.
func copyOperatorManifests(repoRoot, deployDir string) error {
	manifests := []struct{ path, name string }{
		{"ocp-tigera-operator-no-resource-loading.yaml", "operator.yaml"},
		{"ocp/02-role-tigera-operator.yaml", "role.yaml"},
		// The binding is required unlike in earlier bundle generation. The
		// 'operator-sdk generate bundle' command combines clusterroles bound to
		// service accounts. The resulting permissions is set to the CSV's
		// spec.install.clusterPermissions field.
		{"ocp/02-rolebinding-tigera-operator.yaml", "rolebinding-tigera-operator.yaml"},
	}
	for _, m := range manifests {
		if err := copyFile(filepath.Join(repoRoot, ocpManifestDir, m.path), filepath.Join(deployDir, m.name)); err != nil {
			return err
		}
	}
	return nil
}

func copySampleCRs(repoRoot, deployDir string) error {
	for _, sample := range sampleCRs {
		if err := copyFile(filepath.Join(repoRoot, sample), filepath.Join(deployDir, filepath.Base(sample))); err != nil {
			return err
		}
	}
	return nil
}

// copyOperatorCRDs copies over the operator CRDs required for Calico. They are
// shipped as committed: 'make gen-files' writes one document per file with no
// separators, which is what operator-sdk expects.
func copyOperatorCRDs(repoRoot, crdDir string) error {
	for _, crd := range operatorCRDs {
		if err := copyFile(filepath.Join(repoRoot, operatorCRDDir, crd), filepath.Join(crdDir, crd)); err != nil {
			return err
		}
	}
	return nil
}

func copyCalicoCRDs(repoRoot, crdDir string) error {
	for _, resource := range calicoResources {
		logrus.Infof("Copying libcalico-go CRD %s", resource)
		name := fmt.Sprintf("crd.projectcalico.org_%s.yaml", resource)
		if err := copyFile(filepath.Join(repoRoot, calicoCRDDir, name), filepath.Join(crdDir, name)); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	logrus.Debugf("Copying %s to %s", src, dst)

	content, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	if err := os.WriteFile(dst, content, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}
	return nil
}

// editLines rewrites a file through the given transform, one element per line.
func editLines(path string, transform func([]string) []string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	out := strings.Join(transform(lines), "\n") + "\n"
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// filterLines drops every line the predicate matches.
func filterLines(lines []string, drop func(string) bool) []string {
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if !drop(line) {
			kept = append(kept, line)
		}
	}
	return kept
}
