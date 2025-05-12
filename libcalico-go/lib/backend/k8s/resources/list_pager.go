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
	"sync/atomic"

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
	// Wrap our incoming listFunc with one that stashes the revision and number
	// of items we've seen so far.  This allows us to use the more efficient
	// EachListItem() method, while also capturing the list metadata that we
	// need.
	listResourceVersion := ""
	var numItemsLoaded atomic.Int64 // listFunc is called from background goroutine.
	listFunc = func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		obj, err := listFunc(ctx, opts)
		m, err := meta.ListAccessor(obj)
		if err != nil {
			return nil, err
		}
		if m.GetResourceVersion() != "" {
			listResourceVersion = m.GetResourceVersion()
		}
		numItemsLoaded.Add(int64(meta.LenList(obj)))
		return obj, err
	}
	lp := pager.New(listFunc)

	opts := metav1.ListOptions{ResourceVersion: revision}
	if revision != "" {
		opts.ResourceVersionMatch = metav1.ResourceVersionMatchNotOlderThan
	}

	var kvps []*model.KVPair
	err := lp.EachListItem(ctx, opts, func(obj runtime.Object) error {
		res := obj.(Resource)
		result, err := toKVPs(res)
		if err != nil {
			log.WithError(err).WithField("Item", res).Warning("Unable to process resource, skipping")
			return nil
		}
		if result != nil {
			if kvps == nil {
				// Try to guess a suitable result slice capacity.  In practice,
				// this will be the size of the first page (but that's usually
				// the only page.)
				ratio := len(result)
				kvps = make([]*model.KVPair, 0, int(numItemsLoaded.Load())*ratio)
			}
			kvps = append(kvps, result...)
		}
		return nil
	})
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}

	if listResourceVersion == "" {
		log.WithField("list", list).Panic("Failed to extract resource version from list.")
	}

	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: listResourceVersion,
	}, nil
}
