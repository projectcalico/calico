// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"fmt"
	"strings"
)

type errInvalidKey struct {
	k string
}

func (e errInvalidKey) Error() string {
	return fmt.Sprintf("invalid key '%s'", e.k)
}

// NamespaceAndNameFromKey returns the namespace and name for a given k8s etcd-style key.
// This function is intended to be used in a Calico based storage.Interface.
//
// The first return value is the namespace. The namespace will be empty if
// hasNamespace is set to false or when the key is root scoped like for
// list/watch calls.
// The second return value is the name and will
// not be empty if the error is nil. The error will be non-nil if the key was
// malformed, in which case all other return values will be empty strings.
//
// Example Namespaced resource key: projectcalico.org/networkpolicies/default/my-first-policy
// OR projectcalico.org/globalpolicies/my-first-policy
// OR projectcalico.org/networkpolicies (root scope for list/watch operations)
func NamespaceAndNameFromKey(key string, hasNamespace bool) (ns string, name string, err error) {
	spl := strings.Split(key, "/")
	splLen := len(spl)

	if splLen == 2 {
		// slice has neither name nor namespace
		err = nil
	} else if splLen == 3 && !hasNamespace {
		// slice has name
		name = spl[2]
	} else if splLen == 3 && hasNamespace {
		// slice has namespace and no name
		ns = spl[2]
	} else if splLen == 4 && hasNamespace {
		// slice has namespace and name
		ns = spl[2]
		name = spl[3]
	} else {
		err = errInvalidKey{k: key}
	}
	return
}
