// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"k8s.io/apiserver/pkg/registry/generic"
)

const (
	PolicyResource string = "policy"
)

type Options struct {
	RESTOptions generic.RESTOptions
}
