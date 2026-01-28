// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package utils

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

const (
	// ProductName is used in the release process to identify the product.
	ProductName = CalicoProductName

	// Calico is the product name for projectcalico.
	Calico = "calico"

	// CalicoRepoName is the name of the projectcalico repo.
	CalicoRepoName = Calico

	// BirdRepoName is the name of the bird repo.
	BirdRepoName = "bird"

	// CalicoProductCode is the code for projectcalico.
	CalicoProductCode = "os"

	// CalicoProductName is the name of the projectcalico product.
	CalicoProductName = "Calico"

	// ProjectCalicoOrg is the name of the Project Calico organization.
	ProjectCalicoOrg = "projectcalico"

	// TigeraOrg is the name of the Tigera organization.
	TigeraOrg = "tigera"

	// TigeraOperatorChart is the name of the Tigera Operator Helm chart.
	TigeraOperatorChart = "tigera-operator"

	// CalicoCRDsChart is the name of the crd.projectcalico.org/v1 CRD helm chart.
	CalicoCRDsChart = "crd.projectcalico.org.v1"

	// CalicoHelmRepoURL is the URL for the Calico Helm charts.
	CalicoHelmRepoURL = "https://docs.tigera.io/calico/charts"
)

var once sync.Once

var (
	ImageReleaseDirs = []string{
		"apiserver",
		"app-policy",
		"calicoctl",
		"cni-plugin",
		"goldmane",
		"guardian",
		"key-cert-provisioner",
		"kube-controllers",
		"node",
		"pod2daemon",
		"third_party/envoy-gateway",
		"third_party/envoy-proxy",
		"third_party/envoy-ratelimit",
		"typha",
		"whisker",
		"whisker-backend",
	}
	releaseImages = []string{}
)

func initReleaseImages() {
	rootDir, err := command.GitDir()
	if err != nil {
		logrus.Panicf("Cannot determine root git dir: %v", err)
	}
	images, err := BuildReleaseImageList(rootDir, ImageReleaseDirs...)
	if err != nil {
		logrus.Panicf("Cannot build release images list for release dirs[%s]: %v", strings.Join(ImageReleaseDirs, ","), err)
	}
	releaseImages = images
}

func ReleaseImages() []string {
	once.Do(initReleaseImages)
	return slices.Clone(releaseImages)
}

// buildImages returns the list of images built by the given directory.
// It does this by calling a make target that returns the values of BUILD_IMAGES and WINDOWS_IMAGE (if set).
func buildImages(dir string) ([]string, error) {
	out, err := command.MakeInDir(dir, []string{"-s", "build-images"}, nil)
	if err != nil {
		logrus.Error(out)
		return nil, fmt.Errorf("failed to get images for release dir %s: %w", dir, err)
	}
	return strings.Fields(out), nil
}

// BuildReleaseImageList builds a list of images to be released from the given directories.
func BuildReleaseImageList(rootDir string, dirs ...string) ([]string, error) {
	if len(dirs) == 0 {
		logrus.WithField("root_dir", rootDir).Warnf("No image release dirs specified, will get images from root dir instead")
		return buildImages(rootDir)
	}
	combinedImages := []string{}
	for _, d := range dirs {
		dir := filepath.Join(rootDir, d)
		images, err := buildImages(dir)
		if err != nil {
			return nil, err
		}
		combinedImages = append(combinedImages, images...)
	}
	return combinedImages, nil
}
