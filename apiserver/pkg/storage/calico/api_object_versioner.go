// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"strconv"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	k8sStorage "k8s.io/apiserver/pkg/storage"
)

// APIObjectVersioner implements versioning and extracting etcd node information
// for objects that have an embedded ObjectMeta or ListMeta field.
type APIObjectVersioner struct {
	*k8sStorage.APIObjectVersioner
}

// ObjectResourceVersion implements Versioner
func (a APIObjectVersioner) ObjectResourceVersion(obj runtime.Object) (uint64, error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return 0, err
	}
	version := accessor.GetResourceVersion()
	if len(version) == 0 {
		return 0, nil
	}

	return strconv.ParseUint(version, 10, 64)
}
