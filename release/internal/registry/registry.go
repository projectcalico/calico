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
	"strings"

	"github.com/sirupsen/logrus"
)

// Registry represents a container registry.
type Registry interface {
	URL() string
	Token(img ImageRef) (string, error)
	TokenURL(scope string) string
	ManifestURL(img ImageRef) string
}

// GetRegistry returns a Registry based on the registry string.
func GetRegistry(registry string) Registry {
	switch registry {
	case QuayRegistry:
		return &Quay{}
	case DockerRegistry:
		return &Docker{}
	case GCRRegistry:
		return &GCR{}
	default:
		if strings.Contains(registry, GCRRegistry) {
			return NewGCRRegistry(registry)
		} else if strings.Contains(registry, GARSuffix) {
			return NewGAR(registry)
		}
		logrus.WithField("registry", registry).Fatal("Unknown registry")
	}
	return nil
}
