// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package convert

import (
	"fmt"
	"strconv"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
)

const (
	containerTypha = "calico-typha"
)

func checkTypha(c *components, _ *operatorv1.Installation) error {
	// No validation required.
	return nil
}

// handleTyphaMetrics is a migration handler which detects custom prometheus settings for typha and
// carries those options forward via the TyphaMetricsPort field.
func handleTyphaMetrics(c *components, install *operatorv1.Installation) error {
	if c.typha == nil {
		return nil
	}
	metricsEnabled, err := getEnv(ctx, c.client, c.typha.Spec.Template.Spec, ComponentTypha, containerTypha, "TYPHA_PROMETHEUSMETRICSENABLED")
	if err != nil {
		return err
	}
	if metricsEnabled != nil && strings.ToLower(*metricsEnabled) == "true" {
		var _9091 int32 = 9091
		install.Spec.TyphaMetricsPort = &_9091
		port, err := getEnv(ctx, c.client, c.typha.Spec.Template.Spec, ComponentTypha, containerTypha, "TYPHA_PROMETHEUSMETRICSPORT")
		if err != nil {
			return err
		}
		if port != nil {
			p, err := strconv.ParseInt(*port, 10, 32)
			if err != nil || p <= 0 || p > 65535 {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("invalid port defined in TYPHA_PROMETHEUSMETRICSPORT=%s", *port),
					component: ComponentTypha,
					fix:       "adjust it to be within the range of 1-65535 or remove the env var",
				}
			}
			i := int32(p)
			install.Spec.TyphaMetricsPort = &i
		}
	}

	return nil
}
