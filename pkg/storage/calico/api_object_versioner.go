// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	etcd "k8s.io/apiserver/pkg/storage/etcd3"

	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
)

// APIObjectVersioner implements versioning and extracting etcd node information
// for objects that have an embedded ObjectMeta or ListMeta field.
type APIObjectVersioner struct {
	*etcd.APIObjectVersioner
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
	if strings.ContainsRune(version, '/') == true {
		conv := conversion.NewConverter()
		crdNPRev, k8sNPRev, _ := conv.SplitNetworkPolicyRevision(version)
		if crdNPRev == "" && k8sNPRev != "" {
			reason := "kubernetes network policies must be managed through the kubernetes API"
			return 0, errors.NewBadRequest(reason)
		}
		version = crdNPRev
	}
	return strconv.ParseUint(version, 10, 64)
}
