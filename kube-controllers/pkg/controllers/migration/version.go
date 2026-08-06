// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package migration

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	k8sdiscovery "k8s.io/client-go/discovery"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
)

// datastoreMigrationVersions are the DatastoreMigration API versions this
// controller can drive, most preferred first.
var datastoreMigrationVersions = []string{migrationv1.Version, "v1beta1"}

// discoveryPollInterval is how often waitForServedVersion re-checks discovery.
const discoveryPollInterval = time.Second

// waitForServedVersion polls discovery until the DatastoreMigration API turns up.
// Discovery lags the CRD becoming established.
func (m *migrationController) waitForServedVersion(ctx context.Context) (string, error) {
	var version string
	err := wait.PollUntilContextCancel(ctx, discoveryPollInterval, true, func(context.Context) (bool, error) {
		var err error
		version, err = resolveServedVersion(m.k8sClient.Discovery())
		if err != nil {
			logrus.WithError(err).Debug("Waiting for the DatastoreMigration API to appear in discovery")
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return "", err
	}
	return version, nil
}

// resolveServedVersion returns the preferred DatastoreMigration version the
// cluster serves. A v3.32 CRD only serves v1beta1.
func resolveServedVersion(disco k8sdiscovery.DiscoveryInterface) (string, error) {
	for _, version := range datastoreMigrationVersions {
		gv := schema.GroupVersion{Group: migrationv1.Group, Version: version}
		resources, err := disco.ServerResourcesForGroupVersion(gv.String())
		if err != nil {
			if kerrors.IsNotFound(err) {
				continue
			}
			return "", fmt.Errorf("listing resources for %s: %w", gv, err)
		}

		for _, resource := range resources.APIResources {
			if resource.Name == migrationv1.DatastoreMigrationGVR.Resource {
				return version, nil
			}
		}
	}
	return "", fmt.Errorf("no served version of %s", datastoreMigrationCRDName)
}
