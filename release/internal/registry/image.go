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

package registry

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/reference"
	"github.com/sirupsen/logrus"
)

// ImageMap maps the image name to the repository.
var ImageMap = map[string]string{
	"typha":                     "calico/typha",
	"calicoctl":                 "calico/ctl",
	"flannel":                   "coreos/flannel",
	"flexvol":                   "calico/pod2daemon-flexvol",
	"key-cert-provisioner":      "calico/key-cert-provisioner",
	"csi-node-driver-registrar": "calico/node-driver-registrar",
}

// privateImages is a list of images that require authentication.
var privateImages = []string{}

// ImageRef represents a container image.
type ImageRef struct {
	ref reference.Named
}

// Repository returns the repository part of the image.
func (i ImageRef) Repository() string {
	return reference.Path(i.ref)
}

// Tag returns the tag part of the image.
func (i ImageRef) Tag() string {
	return reference.TagNameOnly(i.ref).(reference.NamedTagged).Tag()
}

func (i ImageRef) Registry() Registry {
	domain := reference.Domain(i.ref)
	return GetRegistry(domain)
}

func (i ImageRef) RequiresAuth() bool {
	for _, img := range privateImages {
		if i.Repository() == img {
			return true
		}
	}
	return false
}

func ParseImage(img string) ImageRef {
	ref, err := reference.ParseNormalizedNamed(img)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to parse image")
	}
	return ImageRef{ref}
}

// ImageExists checks if an image exists in a registry.
func ImageExists(img ImageRef) (bool, error) {
	registry := img.Registry()
	scope := fmt.Sprintf("repository:%s:pull", img.Repository())
	var token string
	var err error
	if img.RequiresAuth() {
		token, err = getBearerTokenWithDefaultAuth(registry, scope)
	} else {
		token, err = getBearerToken(registry, scope)
	}
	if err != nil {
		return false, err
	}
	manifestURL := registry.ManifestURL(img)
	logrus.WithFields(logrus.Fields{
		"image":       img,
		"manifestURL": manifestURL,
	}).Debug("Checking if image exists")
	req, err := http.NewRequest(http.MethodGet, manifestURL, nil)
	if err != nil {
		logrus.WithError(err).Error("Failed to create request")
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	// Docker Hub requires the "Accept" header to be set for manifest requests.
	// While it is forgiving in most cases, windows images request will fail without it.
	req.Header.Set("Accept", manifestlist.MediaTypeManifestList)
	resp, err := http.DefaultClient.Do(req.WithContext(context.Background()))
	if err != nil {
		logrus.WithError(err).Error("Failed to get manifest")
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	} else if resp.StatusCode == http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unable to find image: %s", body)
	}
	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}
