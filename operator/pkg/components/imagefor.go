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

package components

import (
	"fmt"

	operator "github.com/projectcalico/calico/operator/api/v1"
)

// Image keys name the images a variant supplies its own build of. The key is the
// image's own name, so it selects an entry from CalicoImages or EnterpriseImages.
const (
	ImageKeyCalico     = "calico"
	ImageKeyNode       = "node"
	ImageKeyCNIPlugins = "third-party-cni-plugins"

	ImageKeyNodeWindows = "node-windows"
	ImageKeyCNIWindows  = "cni-windows"

	ImageKeyEnvoyGateway   = "envoy-gateway"
	ImageKeyEnvoyProxy     = "envoy-proxy"
	ImageKeyEnvoyRatelimit = "envoy-ratelimit"

	ImageKeyIstioPilot      = "istio-pilot"
	ImageKeyIstioInstallCNI = "istio-install-cni"
	ImageKeyIstioZTunnel    = "istio-ztunnel"
	ImageKeyIstioProxyv2    = "istio-proxyv2"
)

// ImageKeys is every key ImageFor answers, for the test that holds the keys and the
// component lists in sync.
var ImageKeys = []string{
	ImageKeyCalico, ImageKeyNode, ImageKeyCNIPlugins,
	ImageKeyNodeWindows, ImageKeyCNIWindows,
	ImageKeyEnvoyGateway, ImageKeyEnvoyProxy, ImageKeyEnvoyRatelimit,
	ImageKeyIstioPilot, ImageKeyIstioInstallCNI, ImageKeyIstioZTunnel, ImageKeyIstioProxyv2,
}

// VariantBuild is what a variant supplies about the images it ships.
type VariantBuild struct {
	Images    []Component
	Release   string
	Registry  string
	ImagePath string
}

var (
	// variantImages is the image set this process runs, registered by the variant as
	// it builds its extensions. Nil means the images this build ships.
	variantImages map[string]Component

	// variantRelease is the release those images are tagged at.
	variantRelease string
)

// RegisterVariant declares the images the running variant supplies and where they
// resolve. The process restarts when the variant changes, so only one ever registers.
func RegisterVariant(b VariantBuild) {
	variantImages = byImage(b.stamped())
	variantRelease = b.Release
}

// RegisterVariantImages declares images that already carry their own defaults.
func RegisterVariantImages(imgs []Component) {
	RegisterVariant(VariantBuild{Images: imgs})
}

// UseVariant registers b and returns a function restoring what was there, for tests
// that render one variant while the suite covers both.
func UseVariant(b VariantBuild) func() {
	prevImages, prevRelease := variantImages, variantRelease
	RegisterVariant(b)
	return func() {
		variantImages, variantRelease = prevImages, prevRelease
	}
}

// UseImages is UseVariant for images that carry their own defaults.
func UseImages(imgs []Component) func() {
	return UseVariant(VariantBuild{Images: imgs})
}

// VariantRelease is the release the running variant's images are tagged at.
func VariantRelease() string {
	if variantRelease != "" {
		return variantRelease
	}
	return CalicoRelease
}

// stamped returns the images carrying the build's defaults, which a variant declaring
// its components outside this package cannot set on them.
func (b VariantBuild) stamped() []Component {
	if b.Registry == "" && b.ImagePath == "" {
		return b.Images
	}

	d := &variantDefaults{registry: b.Registry, imagePath: b.ImagePath}
	out := make([]Component, len(b.Images))
	for i, c := range b.Images {
		c.defaults = d
		out[i] = c
	}
	return out
}

func byImage(imgs []Component) map[string]Component {
	if len(imgs) == 0 {
		return nil
	}
	m := make(map[string]Component, len(imgs))
	for _, c := range imgs {
		m[c.Image] = c
	}
	return m
}

// calicoImages is what this build ships, resolved when no variant registered its own.
var calicoImages = byImage(CalicoImages)

// ImageFor returns the image the running variant supplies for key. A miss is an error
// rather than a fallback to another image, which would ship the wrong one silently.
func ImageFor(key string) (Component, error) {
	imgs := variantImages
	if imgs == nil {
		imgs = calicoImages
	}
	c, ok := imgs[key]
	if !ok {
		return Component{}, fmt.Errorf("no image named %q", key)
	}
	return c, nil
}

// ReferenceFor returns the fully qualified image the running variant supplies for key,
// honoring the installation's registry and image path and any ImageSet.
func ReferenceFor(key string, in *operator.InstallationSpec, is *operator.ImageSet) (string, error) {
	c, err := ImageFor(key)
	if err != nil {
		return "", err
	}
	return GetReference(c, in.Registry, in.ImagePath, in.ImagePrefix, is)
}
