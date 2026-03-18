// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package postrelease

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

func TestOperatorPrintedImagesInExpectedList(t *testing.T) {
	t.Parallel()

	checkVersion(t, operatorVersion)
	checkImages(t, images)

	fqOperatorImage := fmt.Sprintf("%s/%s:%s", operator.DefaultRegistry, operator.DefaultImage, operatorVersion)

	// Pull the operator image.
	t.Logf("Pulling operator image %s", fqOperatorImage)
	pullCmd := exec.Command("docker", "pull", fqOperatorImage)
	if out, err := pullCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to pull operator image %s: %v\n%s", fqOperatorImage, err, string(out))
	}

	// Run the operator image with --print-images=list to get the list of images it uses.
	t.Logf("Running operator image %s with --print-images=list", fqOperatorImage)
	runCmd := exec.Command("docker", "run", "--rm", fqOperatorImage, "--print-images=list")
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run operator image %s with --print-images=list: %v\n%s", fqOperatorImage, err, string(out))
	}

	// Build a set of expected image names from the images flag.
	expectedImages := make(map[string]bool)
	for image := range strings.SplitSeq(images, " ") {
		if image != "" {
			expectedImages[image] = true
		}
	}

	// Parse the output and check that every quay.io/calico image is in our expected list.
	tigeraPrefix := registry.DefaultCalicoRegistry + "/"
	var missing []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, tigeraPrefix) {
			continue
		}
		// Extract the image name from the fully qualified image reference.
		// e.g. "quay.io/calico/node:v3.31.1" -> "node"
		withoutRegistry := strings.TrimPrefix(line, tigeraPrefix)
		imageName, _, _ := strings.Cut(withoutRegistry, ":")
		if imageName == "" {
			continue
		}

		// The operator image itself is not expected in the images list.
		if strings.Contains(operator.DefaultImage, imageName) {
			continue
		}

		if !expectedImages[imageName] {
			missing = append(missing, fmt.Sprintf("%s (from %s)", imageName, line))
		}
	}

	if len(missing) > 0 {
		t.Fatalf("The following quay.io/calico images printed by the operator are not in the expected images list:\n  %s\nExpected images: %s",
			strings.Join(missing, "\n  "),
			images)
	}
	t.Logf("All quay.io/calico images from operator --print-images=list are in the expected images list")
}
