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
	"path"

	operator "github.com/projectcalico/calico/operator/api/v1"
)

// Image keys name the images a variant supplies its own build of. The key is the
// image's own name, so it selects an entry from CalicoImages or the registered build.
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

// Build is what a variant supplies about the images it ships.
type Build struct {
	Images  []Component
	Release string
}

var (
	// buildImages is the image set this process runs, registered by the variant at
	// startup. Nil means the images this build ships.
	buildImages map[string]Component

	// buildRelease is the release those images are tagged at.
	buildRelease string
)

// RegisterBuild declares the images the running variant supplies, and panics on an
// image with no name or no variant. Only one variant registers, since the process
// restarts when it changes.
func RegisterBuild(b Build) {
	for _, c := range b.Images {
		// An unnamed image keys the same entry as every other one, so the build would
		// ship whichever won.
		if c.Image == "" {
			panic("build declares an image with no name")
		}

		if c.Variant == (Variant{}) {
			panic(fmt.Sprintf("component %q names no variant", c.Image))
		}
	}

	buildImages = byImage(b.Images)
	buildRelease = b.Release
}

// UseBuild registers b and returns a function restoring what was there, for tests
// that render one variant while the suite covers both.
func UseBuild(b Build) func() {
	prevImages, prevRelease := buildImages, buildRelease
	RegisterBuild(b)
	return func() {
		buildImages, buildRelease = prevImages, prevRelease
	}
}

// BuildRelease is the release the running variant's images are tagged at.
func BuildRelease() string {
	if buildRelease != "" {
		return buildRelease
	}
	return CalicoRelease
}

// KnownImage reports whether name is an image this build ships, spelled the way an
// ImageSet lists it. The image path is part of the name, so a variant's images are
// only known once it registers.
func KnownImage(name string) bool {
	for _, c := range CalicoImages {
		if name == path.Join(CalicoImagePath, c.Image) {
			return true
		}
	}

	for _, c := range buildImages {
		_, imagePath := getDefaults(c)
		if name == path.Join(imagePath, c.Image) {
			return true
		}
	}
	return false
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
	imgs := buildImages
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
