// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package utils

import (
	"context"
	"fmt"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// TestResourceLabel is a label that is applied to any Calico resource created by the e2e tests.
	// It's used to identify resources that should be cleaned up.
	TestResourceLabel = "projectcalico.org/e2e"
)

// CleanDatastore removes any resources that a previous test may have created.
// It's intended to be called in the BeforeEach of a test in order to ensure a
// clean starting environment.
func CleanDatastore(cli client.Client) error {
	return errorRetry("CleanDatastore", func() error {
		logrus.Info("Cleaning any left-over datastore resources")

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Clean up HEPs first; if we delete GNPs first then we can end up with default deny and block
		// traffic (if failsafe ports aren't configured correctly for this env).
		heps := &v3.HostEndpointList{}
		err := cli.List(ctx, heps)
		if err != nil {
			return fmt.Errorf("failed to list host endpoints: %w", err)
		}
		logrus.Info("Cleaning left-over HEPs")
		for _, hep := range heps.Items {
			// Keep auto or non-cluster host endpoints.
			isAutoHostEndpoint := hep.Labels["projectcalico.org/created-by"] == "calico-kube-controllers"
			isNonClusterHostEndpoint := hep.Labels["hostendpoint.projectcalico.org/type"] == "nonclusterhost"
			if isAutoHostEndpoint || isNonClusterHostEndpoint {
				logrus.WithField("name", hep.Name).Info("Skipping deletion of auto or non-cluster host endpoint")
			} else {
				err = cli.Delete(ctx, &hep)
				if err != nil {
					return err
				}
			}
		}

		// Clean up Calico network policies.
		nps := &v3.NetworkPolicyList{}
		err = cli.List(ctx, nps)
		if err != nil {
			return err
		}

		// Filter-out any policies in the allow-tigera tier. These are included
		// with Calico Enterprise and not provisioned by the tests.
		logrus.Info("Cleaning any left-over network policies")
		for _, np := range nps.Items {
			if np.Spec.Tier != "allow-tigera" && np.Namespace != "addon-policies" {
				if err = cli.Delete(ctx, &np); err != nil {
					return fmt.Errorf("failed to delete network policy %s: %w", np.Name, err)
				}
			}
		}

		// Clean up GNPs.
		gnps := &v3.GlobalNetworkPolicyList{}
		err = cli.List(ctx, gnps)
		if err != nil {
			return err
		}
		// Filter-out any policies in the allow-tigera tier. These are included
		// with Calico Enterprise and not provisioned by the tests.
		logrus.Info("Cleaning left-over GNPs")
		for _, gnp := range gnps.Items {
			if gnp.Spec.Tier != "allow-tigera" {
				err = cli.Delete(ctx, &gnp)
				if err != nil {
					return err
				}
			}
		}

		// Clean up tiers.
		tiers := &v3.TierList{}
		err = cli.List(ctx, tiers)
		if err != nil {
			return err
		}
		logrus.Info("Cleaning left-over tiers")
		for _, tier := range tiers.Items {
			// Only clean up tiers that have the projectcalico.org/e2e label.
			if _, ok := tier.Labels[TestResourceLabel]; ok {
				err = cli.Delete(ctx, &tier)
				if err != nil {
					return err
				}
			}
		}

		return nil
	})
}

// errorRetry is a local helper for retrying a function on error.
func errorRetry(desc string, f func() error) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = f(); err != nil {
			logrus.WithError(err).Infof("Retrying function (%s) after error", desc)
			continue
		}
		return nil
	}
	return fmt.Errorf("function %s failed after 5 retries: %v", desc, err)
}
