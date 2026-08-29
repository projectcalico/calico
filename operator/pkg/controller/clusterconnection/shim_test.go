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

// This file is here so that we can export a constructor to be used by the tests in the clusterconnection_test package, but since
// this is an _test file it will only be available for when running tests.

package clusterconnection

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/enterprise"
	eoptions "github.com/projectcalico/calico/operator/pkg/enterprise/options"
)

func NewReconcilerWithShims(
	cli client.Client,
	schema *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	tierWatchReady *utils.ReadyFlag,
	clusterInfoWatchReady *utils.ReadyFlag,
) reconcile.Reconciler {
	opts := options.ControllerOptions{
		ShutdownContext: context.Background(),
		Extensions:      enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{}),
		Variant:         operatorv1.CalicoEnterprise,
	}

	return newReconciler(cli, schema, status, provider, tierWatchReady, clusterInfoWatchReady, opts)
}
