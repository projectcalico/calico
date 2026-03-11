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

package utils

import (
	"context"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/projectcalico/calico/api/pkg/apis/projectcalico/v3"
)

// UpdateFelixConfig applies a mutation to the default FelixConfiguration.
// The mutate callback receives the current spec and should modify it in place.
func UpdateFelixConfig(cli ctrlclient.Client, mutate func(spec *v3.FelixConfigurationSpec)) error {
	cc := v3.NewFelixConfiguration()
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, cc)
	if err != nil {
		return err
	}

	mutate(&cc.Spec)
	return cli.Update(context.Background(), cc)
}
