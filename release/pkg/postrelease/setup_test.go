// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package postrelease

import (
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var (
	linuxArches  = []string{"amd64", "arm64", "s390x", "ppc64le"}
	darwinArches = []string{"amd64", "arm64"}
)

var (
	releaseVersion, operatorVersion, flannelVersion  string
	githubOrg, githubRepo, githubRemote, githubToken string
	images                                           string
	httpTimeout                                      time.Duration

	// The default timeout duration
	httpDefaultTimeout = 10 * time.Second
)

func init() {
	flag.StringVar(&releaseVersion, "release-version", "", "Version for the release")
	flag.StringVar(&operatorVersion, "operator-version", "", "Version for Tigera operator")
	flag.StringVar(&flannelVersion, "flannel-version", "", "Version for flannel")
	flag.StringVar(&githubOrg, "github-org", utils.ProjectCalicoOrg, "GitHub organization")
	flag.StringVar(&githubRepo, "github-repo", utils.CalicoRepoName, "GitHub repository")
	flag.StringVar(&githubRemote, "github-repo-remote", utils.DefaultRemote, "GitHub repository remote")
	flag.StringVar(&images, "images", "", "List of images to check")
	flag.StringVar(&githubToken, "github-token", "", "GitHub token")
	flag.DurationVar(&httpTimeout, "http-timeout", httpDefaultTimeout, "HTTP timeout for checking openstack packages")
}

func checkVersion(t testing.TB, version string) {
	t.Helper()
	if version == "" {
		t.Fatal("No version provided")
	}
}

func checkImages(t testing.TB, images string) {
	t.Helper()
	if images == "" {
		t.Fatal("No images provided")
	}
	list := strings.Split(images, " ")
	if len(list) == 0 {
		t.Fatal("No images provided")
	}
	for _, image := range list {
		if strings.Contains(image, operator.DefaultImage) {
			t.Fatal("Operator images are checked separately, do not include in list of images to check")
		}
	}
}
