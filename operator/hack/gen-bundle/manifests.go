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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"go.yaml.in/yaml/v3"
)

// calicoBaseURL is the base path for the Calico repository, used to download
// the manifests and CRDs that the bundle ships.
const calicoBaseURL = "https://raw.githubusercontent.com/projectcalico/calico"

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
// 'operator-sdk bundle validate'.
var sampleCRs = []string{
	"config/samples/operator_v1_installation.yaml",
	"config/samples/operator_v1_imageset.yaml",
}

const (
	// operatorCRDDir holds the committed operator CRDs. 'make gen-files' and the
	// CI dirty-check keep them current, so the bundle ships them as they are.
	operatorCRDDir = "pkg/crds/operator"

	// calicoVersionsPath names the Calico release the operator ships.
	calicoVersionsPath = "config/calico_versions.yml"
)

var getManifestsCommand = &cli.Command{
	Name:  "get-manifests",
	Usage: "Stage the Calico and operator manifests that 'operator-sdk generate bundle' reads to build a ClusterServiceVersion",
	Flags: []cli.Flag{crdDirFlag, deployDirFlag},
	Action: func(ctx context.Context, c *cli.Command) error {
		return getManifests(ctx, c.String(crdDirFlag.Name), c.String(deployDirFlag.Name))
	},
}

func getManifests(ctx context.Context, crdDir, deployDir string) error {
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

	logrus.Infof("Building bundle from %s", deployDir)

	baseURL, err := calicoURL()
	if err != nil {
		return err
	}

	if err := downloadOperatorManifests(ctx, baseURL, deployDir); err != nil {
		return err
	}
	if err := copySampleCRs(deployDir); err != nil {
		return err
	}
	if err := copyOperatorCRDs(crdDir); err != nil {
		return err
	}
	return downloadCalicoCRDs(ctx, baseURL, crdDir)
}

// calicoURL returns the base URL of the Calico release that the operator ships,
// which is the version the manifests and CRDs are downloaded from.
func calicoURL() (string, error) {
	content, err := os.ReadFile(calicoVersionsPath)
	if err != nil {
		return "", fmt.Errorf("could not find Calico versions file: %w", err)
	}
	var cfg struct {
		Components map[string]struct {
			Version string `yaml:"version"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return "", fmt.Errorf("parsing %s: %w", calicoVersionsPath, err)
	}
	if cfg.Components["typha"].Version == "" {
		return "", fmt.Errorf("no typha version in %s", calicoVersionsPath)
	}
	return fmt.Sprintf("%s/%s", calicoBaseURL, cfg.Components["typha"].Version), nil
}

// downloadOperatorManifests downloads the operator manifests. For CSV generation
// we use a version of the operator deployment manifest that doesn't include an
// init container and volumes for creating install-time resources.
func downloadOperatorManifests(ctx context.Context, baseURL, deployDir string) error {
	manifests := []struct{ path, name string }{
		{"manifests/ocp-tigera-operator-no-resource-loading.yaml", "operator.yaml"},
		{"manifests/ocp/02-role-tigera-operator.yaml", "role.yaml"},
		// The binding is required unlike in earlier bundle generation. The
		// 'operator-sdk generate bundle' command combines clusterroles bound to
		// service accounts. The resulting permissions is set to the CSV's
		// spec.install.clusterPermissions field.
		{"manifests/ocp/02-rolebinding-tigera-operator.yaml", "rolebinding-tigera-operator.yaml"},
	}
	for _, m := range manifests {
		if err := download(ctx, baseURL+"/"+m.path, filepath.Join(deployDir, m.name)); err != nil {
			return err
		}
	}
	return nil
}

func copySampleCRs(deployDir string) error {
	for _, sample := range sampleCRs {
		if err := copyFile(sample, filepath.Join(deployDir, filepath.Base(sample))); err != nil {
			return err
		}
	}
	return nil
}

// copyOperatorCRDs copies over and cleans up the operator CRDs required for Calico.
func copyOperatorCRDs(crdDir string) error {
	for _, crd := range operatorCRDs {
		dst := filepath.Join(crdDir, crd)
		if err := copyFile(filepath.Join(operatorCRDDir, crd), dst); err != nil {
			return err
		}
		// Remove empty lines and the three dashes that separate directives.
		if err := editLines(dst, func(lines []string) []string {
			return filterLines(lines, func(line string) bool {
				return line == "" || line == "---"
			})
		}); err != nil {
			return err
		}
	}
	return nil
}

func downloadCalicoCRDs(ctx context.Context, baseURL, crdDir string) error {
	for _, resource := range calicoResources {
		logrus.Infof("Downloading libcalico-go CRD %s", resource)
		name := fmt.Sprintf("crd.projectcalico.org_%s.yaml", resource)
		url := fmt.Sprintf("%s/libcalico-go/config/crd/%s", baseURL, name)
		if err := download(ctx, url, filepath.Join(crdDir, name)); err != nil {
			return err
		}
	}
	return nil
}

func download(ctx context.Context, url, dst string) error {
	logrus.Debugf("Downloading %s to %s", url, dst)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: %s", url, resp.Status)
	}

	f, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("creating %s: %w", dst, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
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
