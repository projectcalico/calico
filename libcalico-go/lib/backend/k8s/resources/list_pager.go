// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package resources

import (
	"context"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/pager"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// pagedList performs a paginated list operation against the Kubernetes API using the given
// information.
func pagedList(
	ctx context.Context,
	log *logrus.Entry,
	revision string,
	list model.ListInterface,
	toKVPs func(Resource) ([]*model.KVPair, error),
	listFunc func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error),
) (
	*model.KVPairList,
	error,
) {
	lp := pager.New(listFunc)
	opts := metav1.ListOptions{ResourceVersion: revision}
	if revision != "" {
		opts.ResourceVersionMatch = metav1.ResourceVersionMatchNotOlderThan
	}
	result, isPaged, err := lp.List(ctx, opts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	logCtx := log.WithField("pagedList", isPaged)
	logCtx.Debug("List() call completed, convert results")

	// For each item in the response, convert it to a KVPair and add it to the list.
	kvps := []*model.KVPair{}
	err = meta.EachListItem(result, func(obj runtime.Object) error {
		res := obj.(Resource)
		result, err := toKVPs(res)
		if err != nil {
			logCtx.WithError(err).WithField("Item", res).Warning("unable to process resource, skipping")
			return nil
		}
		if result != nil {
			kvps = append(kvps, result...)
		}
		return nil
	})
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}

	// Extract list revision information.
	m, err := meta.ListAccessor(result)
	if err != nil {
		return nil, err
	}
	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: m.GetResourceVersion(),
	}, nil
}
