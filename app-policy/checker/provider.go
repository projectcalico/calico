// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package checker

import (
	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/projectcalico/calico/app-policy/policystore"
)

type CheckProvider interface {
	Name() string
	EnabledForRequest(*policystore.PolicyStore, *authz.CheckRequest) bool
	Check(*policystore.PolicyStore, *authz.CheckRequest) (*authz.CheckResponse, error)
}
