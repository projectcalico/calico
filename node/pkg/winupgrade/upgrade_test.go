// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

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

package winupgrade

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

const (
	nodeShortImageTag     = "example.com/node:v3.21.0"
	nodeDockerImageTag    = "docker.io/calico/node:v3.21.0"
	nodeDockerImageDigest = "docker.io/calico/node@sha256:1a54e9ad69451473fde398ac63a5f5696712cf38ed00f0deadc4189927b93176"
	nodeQuayImageDigest   = "quay.io/calico/node@sha256:bf87045cbb6c3f9ca39b9724350f728e8dab780b3e6185d413c7f232fb0452bf"

	windowsShortImageTag     = "example.com/calico-windows-upgrade:v3.21.0"
	windowsShortImageTag2    = "my-registry.org/calico-windows-upgrade:v3.21.0"
	windowsDockerImageTag    = "docker.io/calico/windows-upgrade:v3.21.0"
	windowsDockerImageDigest = "docker.io/calico/windows-upgrade@sha256:1aa17a74e3f084e94b0d1f93bdd745c8c88cbb292907ac4fa94d6f206a5e49db"
	windowsQuayImageTag      = "quay.io/calico/windows-upgrade:v3.21.0"

	nodeLongImageTag    = "example.com/tigera/calico/testing/node:v3.21.0"
	windowsLongImageTag = "example.com/tigera/calico/windows-upgrade:v3.21.0"
)

var _ = DescribeTable("verifyImagesShareRegistryPath",
	func(upgradeImage string, nodeImage string, noError bool) {
		err := verifyImagesSharePathPrefix(upgradeImage, nodeImage)
		Expect(err == nil).To(Equal(noError))
	},
	Entry("same prefix, tag", windowsDockerImageTag, nodeDockerImageTag, true),
	Entry("same prefix, digest1", windowsDockerImageTag, nodeDockerImageDigest, true),
	Entry("same prefix, digest2", windowsDockerImageDigest, nodeDockerImageDigest, true),
	Entry("same prefix, short tags", nodeShortImageTag, windowsShortImageTag, true),

	Entry("diff prefix, tag", windowsQuayImageTag, nodeDockerImageTag, false),
	Entry("diff prefix, digest1", windowsDockerImageTag, nodeQuayImageDigest, false),
	Entry("diff prefix, digest2", nodeDockerImageDigest, nodeQuayImageDigest, false),
	Entry("diff prefix, short tags", nodeShortImageTag, windowsShortImageTag2, false),
	Entry("diff prefix, diff lengths", nodeLongImageTag, windowsLongImageTag, false),
)
