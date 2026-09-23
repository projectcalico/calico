// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package networkpolicy

import (
	"context"
	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	liberr "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// PolicyKinds are the tiered policy kinds whose stored name may still carry a
// "default." tier prefix from before v3.32. Non-tiered resources never had one.
var PolicyKinds = []string{
	v3.KindNetworkPolicy,
	v3.KindGlobalNetworkPolicy,
	v3.KindStagedNetworkPolicy,
	v3.KindStagedGlobalNetworkPolicy,
}

// NeedsMigration reports whether a policy is stored under a name that differs
// from its v3 name. Only the default tier is affected: before v3.32 its datastore
// name carried a "default." prefix the v3 name never had, whereas other tiers
// always required the prefix in both, so their names already match.
//
// The name in the Key is the actual v1 ID used in the datastore, whereas the
// ObjectMeta.Name is the v3 object name.
func NeedsMigration(p client.Object, k model.ResourceKey) bool {
	return isDefaultTier(p) && k.Name != p.GetName()
}

// MigratePolicyKVP aligns a single policy's datastore name with its v3 name by
// writing a copy under the new name and deleting the old entry. It reports
// whether a migration was performed. An already-created new entry or an
// already-deleted old entry is treated as success, so the operation is safe to
// repeat after a partially-completed run.
func MigratePolicyKVP(ctx context.Context, bc bapi.Client, kvp *model.KVPair) (bool, error) {
	k, ok := kvp.Key.(model.ResourceKey)
	if !ok {
		return false, fmt.Errorf("unexpected key type %T", kvp.Key)
	}
	p, ok := kvp.Value.(client.Object)
	if !ok {
		return false, fmt.Errorf("unexpected value type %T for %s", kvp.Value, k.Name)
	}
	if !NeedsMigration(p, k) {
		return false, nil
	}

	newKey := k
	newKey.Name = p.GetName()

	_, err := bc.Create(ctx, &model.KVPair{Key: newKey, Value: p.DeepCopyObject()})
	if err != nil {
		if _, ok := err.(liberr.ErrorResourceAlreadyExists); !ok {
			return false, fmt.Errorf("create %s %q: %w", k.Kind, newKey.Name, err)
		}
	}

	_, err = bc.DeleteKVP(ctx, kvp)
	if err != nil {
		if _, ok := err.(liberr.ErrorResourceDoesNotExist); !ok {
			return false, fmt.Errorf("delete %s %q: %w", k.Kind, k.Name, err)
		}
	}

	logrus.WithFields(logrus.Fields{
		"kind":    k.Kind,
		"oldName": k.Name,
		"newName": newKey.Name,
	}).Info("Migrated policy datastore name")
	return true, nil
}

func isDefaultTier(p client.Object) bool {
	tier, ok := names.TierFromPolicy(p)
	if !ok {
		logrus.WithFields(logrus.Fields{
			"namespace": p.GetNamespace(),
			"name":      p.GetName(),
		}).Warn("Could not extract tier from policy object, assuming default")
		return true
	}
	return tier == names.DefaultTierName
}
