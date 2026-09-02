// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v2"
)

var (
	// default images for components that do not specify an image in versions.yml
	// For now, it includes "calico/<imageName>" as well as "<imageName>" to handle
	// older versions.yml files that have not been updated to remove the imagePath.
	defaultImages = map[string]string{
		"cni":                            "cni",
		"cni-windows":                    "cni-windows",
		"dikastes":                       "dikastes",
		"kube-controllers":               "kube-controllers",
		"node":                           "node",
		"node-windows":                   "node-windows",
		"goldmane":                       "goldmane",
		"guardian":                       "guardian",
		"whisker":                        "whisker",
		"whisker-backend":                "whisker-backend",
		"calicoctl":                      "ctl",
		"flexvol":                        "pod2daemon-flexvol",
		"csi":                            "csi",
		"typha":                          "typha",
		"key-cert-provisioner":           "key-cert-provisioner",
		"apiserver":                      "apiserver",
		"envoy-gateway":                  "envoy-gateway",
		"envoy-proxy":                    "envoy-proxy",
		"envoy-ratelimit":                "envoy-ratelimit",
		"eck-elasticsearch":              "unused-image",
		"eck-elasticsearch-operator":     "unused-image",
		"eck-kibana":                     "unused-image",
		"coreos-prometheus":              "unused-image",
		"coreos-alertmanager":            "unused-image",
		"tigera-cni":                     "cni",
		"tigera-cni-windows":             "cni-windows",
		"third-party-cni-plugins":        "third-party-cni-plugins",
		"tigera-third-party-cni-plugins": "third-party-cni-plugins",
		"linseed":                        "linseed",
		"gateway-api-envoy-gateway":      "envoy-gateway",
		"gateway-api-envoy-proxy":        "envoy-proxy",
		"gateway-api-envoy-ratelimit":    "envoy-ratelimit",
		"istio-pilot":                    "istio-pilot",
		"istio-install-cni":              "istio-install-cni",
		"istio-ztunnel":                  "istio-ztunnel",
		"istio-proxyv2":                  "istio-proxyv2",
		"webhooks":                       "webhooks",
		"calico":                         "calico",
	}

	ignoredImages = map[string]struct{}{
		"networking-calico": {},
		"calico-private":    {},
		"manager-proxy":     {},
		"busybox":           {},
		"api":               {},
		"libcalico-go":      {},
	}
)

type Release struct {
	// Title is the Release version and should match the major.minor.patch of the
	// Calico or Enterprise version included in the operator.
	Title      string     `yaml:"title"`
	Components Components `yaml:"components"`
}

type Components map[string]*Component

type Component struct {
	Version   string `yaml:"version"`
	Registry  string `yaml:"registry"`
	ImagePath string `yaml:"imagePath"`
	Image     string `yaml:"image"`
}

// GetComponents parses a versions.yml file, scrubs the data of known issues,
// and returns the data in a Components struct.
func GetComponents(versionsPath string) (Release, error) {
	var cv Release
	v, err := readComponents(versionsPath)
	if err != nil {
		return cv, fmt.Errorf("failed to read components: %v", err)
	}

	cv.Components = make(Components)
	cv.Title = v.Title

	// parse through the components listed in versions.yml to:
	// - add known default images to any components that are missing them.
	// - ignore any components that are not actually images.
	// - validate components are well formed.
	for key, component := range v.Components {
		// Ignore components that are not actually images.
		if _, ignore := ignoredImages[key]; ignore {
			continue
		}

		// Add default image if not specified.
		if component.Image == "" {
			image := defaultImages[key]
			if image == "" {
				return cv, fmt.Errorf("image not specified and no default image available for component %q. "+
					"Either fill in the 'image' field or update this code with a defaultImage. "+
					"If key contains %q, remove it and try again", key, "calico/")
			}
			component.Image = image
		}

		// Ensure that the component is well formed:
		// Version must be specified.
		if component.Version == "" {
			return cv, fmt.Errorf("no version specified for component %q", key)
		}
		// Registry must end with a '/' if specified.
		if component.Registry != "" && !strings.HasSuffix(component.Registry, "/") {
			return cv, fmt.Errorf("registry %q specified for component %q must end with a '/'", component.Registry, key)
		}
		// Image must not contain any '/' characters - indicating an image path.
		imageParts := strings.SplitAfterN(component.Image, "/", 2)
		if len(imageParts) == 2 {
			if component.ImagePath != "" {
				return cv, fmt.Errorf("component '%s' has both imagePath and image with a path. "+
					"Either remove the imagePath field or update the image field to not include a path", key)
			}
			component.ImagePath = imageParts[0]
			component.Image = imageParts[1]
		}
		cv.Components[key] = component
	}

	return cv, nil
}

// readComponents opens a versions.yml file and returns a Release
func readComponents(versionsPath string) (Release, error) {
	var cr Release
	f, err := os.ReadFile(versionsPath)
	if err != nil {
		return cr, err
	}

	if err := yaml.Unmarshal(f, &cr); err != nil {
		return cr, err
	}

	return cr, nil
}

// renderFile writes the rendered template to path, buffering first so a failed
// render leaves any existing file alone.
func renderFile(path, tplFile string, vz Release) error {
	var buf bytes.Buffer
	if err := render(&buf, tplFile, vz); err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func render(w io.Writer, tplFile string, vz Release) error {
	funcs := template.FuncMap{
		"required": requiredComponent,
	}

	name := filepath.Base(tplFile)
	t, err := template.New(name).Funcs(funcs).Option("missingkey=error").ParseFiles(tplFile)
	if err != nil {
		return fmt.Errorf("failed to parse template file file: %v", err)
	}

	return t.Execute(w, vz)
}

// requiredComponent returns the named component, erroring when the versions file
// omits it rather than letting the template render an empty image reference.
func requiredComponent(components Components, key string) (*Component, error) {
	c, ok := components[key]
	if !ok || c == nil {
		return nil, fmt.Errorf("versions file has no entry for required component %q", key)
	}
	return c, nil
}
