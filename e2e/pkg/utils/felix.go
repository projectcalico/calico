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
	"reflect"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// UpdateFelixConfig applies a mutation to the default FelixConfiguration.
// If the mutation results in no change, no update is performed and a no-op
// cleanup function is returned. Otherwise, the returned cleanup function
// restores the spec to its pre-mutation state.
//
// To avoid cleanups clobbering each-other, they should be applied from latest-to-oldest (e.g via DeferCleanup).
// NOTE! Since Felixconfig is a global resource, mutations should only be done in serial tests. Cleanup order cannot
// be guaranteed in parallel tests.
func UpdateFelixConfig(cli ctrlclient.Client, mutate func(spec *v3.FelixConfigurationSpec)) (cleanup func() error, err error) {
	nilFn := func() error {
		return nil
	}
	ctx := context.Background()
	cc := v3.NewFelixConfiguration()
	gCtx, gCancel := context.WithTimeout(ctx, 10*time.Second)
	defer gCancel()
	err = cli.Get(gCtx, ctrlclient.ObjectKey{Name: "default"}, cc)
	if err != nil {
		return nilFn, err
	}

	original := cc.Spec.DeepCopy()
	mutate(&cc.Spec)

	if reflect.DeepEqual(original, &cc.Spec) {
		return nilFn, nil
	}

	wCtx, wCancel := context.WithTimeout(ctx, 10*time.Second)
	defer wCancel()
	if err := cli.Update(wCtx, cc); err != nil {
		return nilFn, err
	}

	return func() error {
		_, err := UpdateFelixConfig(cli, func(spec *v3.FelixConfigurationSpec) {
			*spec = *original
		})
		return err
	}, nil
}
