// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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

package k8s

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	v1scheme "github.com/projectcalico/calico/libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// BackendAPIGroup returns the API group that should be used for the Calico CRD
// backend, based on the configuration and/or auto-discovery of the API server.
func BackendAPIGroup(cfg *apiconfig.CalicoAPIConfigSpec) string {
	if UsingV3CRDs(cfg) {
		return apiv3.GroupVersionCurrent
	}
	return v1scheme.GroupVersion
}

// UsingV3CRDs determines whether or not we should be using the projectcalico.org/v3 API group
// for Calico CRDs, or the crd.projectcalico.org/v1 API group. This is determined either by
// explicit configuration (if specified), or by auto-discovery of the API groups supported by the API server.
func UsingV3CRDs(cfg *apiconfig.CalicoAPIConfigSpec) bool {
	if cfg != nil && cfg.CalicoAPIGroup != "" && cfg.DatastoreType == apiconfig.Kubernetes {
		logrus.WithField("apiGroup", cfg.CalicoAPIGroup).Info("Using explicitly configured Calico API group")
		return cfg.CalicoAPIGroup == apiv3.GroupVersionCurrent
	}

	// Try to perform auto-discovery of the API group, by contacting the API server.
	// If we can't contact the API server, we default to not using v3 CRDs.
	_, cs, err := CreateKubernetesClientset(cfg)
	if err != nil {
		log.WithError(err).Warn("Failed to create clientset, cannot autodiscover API group, defaulting to crd.projectcalico.org/v1")
		return false
	}
	apiGroups, err := cs.Discovery().ServerGroups()
	if err != nil {
		log.WithError(err).Warn("Failed to query API server for supported API groups, cannot autodiscover API group, defaulting to crd.projectcalico.org/v1")
		return false
	}

	v3present, v1present := false, false
	for _, g := range apiGroups.Groups {
		if g.Name == apiv3.GroupName {
			logrus.WithField("apiGroup", g.Name).Info("Discovered v3 Calico API group")
			v3present = true
		}
		if g.Name == v1scheme.GroupName {
			logrus.WithField("apiGroup", g.Name).Info("Discovered v1 Calico API group")
			v1present = true
		}
	}

	// If v3 is present but v1 is not, this means we should use the projectcalico.org/v3 API group.
	// If both are present, it likely means that crd.projectcalico.org/v1 is present and used to implement the
	// projectcalico.org/v3 API group via the API server, so we should use crd.projectcalico.org/v1 directly.
	return v3present && !v1present
}
