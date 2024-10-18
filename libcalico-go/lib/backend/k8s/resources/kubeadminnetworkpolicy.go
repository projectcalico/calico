// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	adminpolicy "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	adminpolicyclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/typed/apis/v1alpha1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// NewKubernetesAdminNetworkPolicyClient returns a new client for interacting with Kubernetes AdminNetworkPolicy objects.
// Note that this client is only intended for use by the felix syncer in KDD mode, and as such is largely unimplemented
// except for the functions required by the syncer.
func NewKubernetesAdminNetworkPolicyClient(
	anpClient *adminpolicyclient.PolicyV1alpha1Client,
) K8sResourceClient {
	return &adminNetworkPolicyClient{
		Converter:         conversion.NewConverter(),
		adminPolicyClient: anpClient,
	}
}

// Implements the api.Client interface for Kubernetes NetworkPolicy.
type adminNetworkPolicyClient struct {
	conversion.Converter
	adminPolicyClient *adminpolicyclient.PolicyV1alpha1Client
}

func (c *adminNetworkPolicyClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on AdminNetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *adminNetworkPolicyClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on AdminNetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Update",
	}
}

func (c *adminNetworkPolicyClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *adminNetworkPolicyClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Debug("Received Delete request on AdminNetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *adminNetworkPolicyClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on AdminNetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Get",
	}
}

func (c *adminNetworkPolicyClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	logContext := log.WithField("Resource", "AdminNetworkPolicy")
	logContext.Debug("Received List request")

	listFunc := func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return c.adminPolicyClient.AdminNetworkPolicies().List(ctx, opts)
	}
	convertFunc := func(r Resource) ([]*model.KVPair, error) {
		anp := r.(*adminpolicy.AdminNetworkPolicy)
		kvp, err := c.K8sAdminNetworkPolicyToCalico(anp)
		// Silently ignore rule conversion errors. We don't expect any conversion errors
		// since the data given to us here is validated by the Kubernetes API. The conversion
		// code ignores any rules that it cannot parse, and we will pass the valid ones to Felix.
		var e *cerrors.ErrorAdminPolicyConversion
		if err != nil && !errors.As(err, &e) {
			return nil, err
		}
		return []*model.KVPair{kvp}, nil
	}
	return pagedList(ctx, logContext, revision, list, convertFunc, listFunc)
}

func (c *adminNetworkPolicyClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// Build watch options to pass to k8s.
	opts := metav1.ListOptions{Watch: true, AllowWatchBookmarks: false}
	_, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}

	opts.ResourceVersion = revision
	log.Debugf("Watching Kubernetes AdminNetworkPolicy at revision %q", revision)
	k8sRawWatch, err := c.adminPolicyClient.AdminNetworkPolicies().Watch(ctx, opts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		anp, ok := r.(*adminpolicy.AdminNetworkPolicy)
		if !ok {
			return nil, errors.New("Kubernetes AdminNetworkPolicy conversion with incorrect k8s resource type")
		}

		return c.K8sAdminNetworkPolicyToCalico(anp)
	}
	return newK8sWatcherConverter(ctx, "Kubernetes AdminNetworkPolicy", converter, k8sRawWatch), nil
}

func (c *adminNetworkPolicyClient) EnsureInitialized() error {
	return nil
}
