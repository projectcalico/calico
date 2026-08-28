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

// package convert reads config from existing Calico installations that are not
// managed by Operator, and generates Operator Config that can be used
// to configure a similar cluster.

package convert

import (
	"context"
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("migration_convert")

var ctx = context.Background()

// NeedsConversion checks if an existing installation of Calico exists which
// is not managed by the Operator.
func NeedsConversion(ctx context.Context, client client.Client) (bool, error) {
	comps, err := getComponents(ctx, client)
	if err != nil {
		return false, err
	}
	return comps != nil, nil
}

// Convert updates an Installation resource based on an existing Calico install (i.e.
// one that is not managed by operator). If the existing installation cannot be represented by an Installation
// resource, an ErrIncompatibleCluster is returned.
func Convert(ctx context.Context, client client.Client) (*operatorv1.Installation, error) {
	comps, err := getComponents(ctx, client)
	if err != nil {
		if kerrors.IsNotFound(err) {
			log.Error(err, "no existing install found: %v", err)
			return nil, nil
		}
		return nil, err
	}

	install := &operatorv1.Installation{}
	for _, hdlr := range handlers {
		if err := hdlr(comps, install); err != nil {
			return nil, err
		}
	}

	// Handle the remaining FelixVars last because we only want to take env vars which weren't accounted
	// for by the other handlers
	if err := handleFelixVars(comps); err != nil {
		return nil, err
	}

	// check for unchecked env vars
	if uncheckedVars := comps.node.uncheckedVars(); len(uncheckedVars) != 0 {
		return nil, ErrIncompatibleCluster{
			err:       fmt.Sprintf("unexpected env vars: %s", uncheckedVars),
			component: ComponentCalicoNode,
			fix:       "remove these environment variables from the calico-node daemonest",
		}
	}

	return install, nil
}
