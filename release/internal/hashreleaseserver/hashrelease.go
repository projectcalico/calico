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

package hashreleaseserver

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/errors"
)

type Hashrelease struct {
	// Name is the name of the hashrelease.
	// When publishing a hashrelease, this is the name of the folder in the server.
	// When getting a hashrelease, this is the full path of the hashrelease folder.
	Name string

	// Hash is the hash of the hashrelease
	Hash string

	// Note is the info about the hashrelease
	Note string

	// Branch is the branch the hashrelease is built from
	Branch string

	Versions version.Data

	// Source is the source of hashrelease content
	Source string

	// Time is the modified time of the hashrelease
	Time time.Time

	// Latest is if the hashrelease is the latest for the stream
	Latest bool

	// Components is the components of the hashrelease
	Components map[string]registry.Component
}

func (h Hashrelease) Stream() string {
	return version.DeterminePublishStream(h.Branch, h.Versions.ProductVersion.FormattedString())
}

func (h Hashrelease) URL() string {
	return fmt.Sprintf("https://%s.%s", h.Name, BaseDomain)
}

func (h Hashrelease) Valid() ([]string, error) {
	componentsToValidate := make(map[string]registry.Component)
	for name, component := range h.Components {
		// Skip components that do not produce images.
		if name == "calico" || name == "calico/api" || name == "networking-calico" {
			continue
		}
		img := registry.ImageMap[name]
		if img != "" {
			component.Image = img
		} else if component.Image == "" {
			component.Image = name
		}
		componentsToValidate[name] = component
	}
	results := make(map[string]imageCheckResult, len(componentsToValidate))
	ch := make(chan imageCheckResult)
	imageList := []string{}
	for name, component := range componentsToValidate {
		imageList = append(imageList, component.String())
		go imgExists(name, component, ch)
	}
	for range componentsToValidate {
		res := <-ch
		results[res.name] = res
	}
	invalidImages := []registry.Component{}
	for name, r := range results {
		logrus.WithFields(logrus.Fields{
			"image":  r.image,
			"exists": r.exists,
		}).Info("Validating image")
		if r.err != nil || !r.exists {
			logrus.WithError(r.err).WithField("image", name).Error("Error checking image")
			invalidImages = append(invalidImages, componentsToValidate[name])
		} else {
			logrus.WithField("image", name).Debug("Image exists")
		}
	}
	if len(invalidImages) > 0 {
		return imageList, errors.ErrInvalidImages{
			ReleaseName:  h.Name,
			Stream:       h.Stream(),
			Versions:     h.Versions,
			FailedImages: invalidImages,
		}
	}
	return imageList, nil
}

type imageCheckResult struct {
	name   string
	image  string
	exists bool
	err    error
}

func imgExists(name string, component registry.Component, ch chan imageCheckResult) {
	r := imageCheckResult{
		name:  name,
		image: component.String(),
	}
	r.exists, r.err = registry.ImageExists(component.ImageRef())
	ch <- r
}
