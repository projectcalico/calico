// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/rest"
)

const (
	SystemNetworkPolicyResourceName = "systemnetworkpolicies"
	SystemNetworkPolicyTPRName      = "system-network-policy.alpha.projectcalico.org"
	SystemNetworkPolicyNamePrefix   = "snp.projectcalico.org/"
)

func NewSystemNetworkPolicies(c *kubernetes.Clientset, r *rest.RESTClient) api.Client {
	return &snpClient{
		clientSet: c,
		tprClient: r,
	}
}

// Implements the api.Client interface for System Network Policies.
type snpClient struct {
	clientSet *kubernetes.Clientset
	tprClient *rest.RESTClient
}

// Create implements the Create method for System Network Policies (exposed
// through the libcalico-go API as standard Policy resources)
func (c *snpClient) Create(kvp *model.KVPair) (*model.KVPair, error) {
	log.WithField("KV", kvp).Debug("Performing System Network Policy Create")
	tpr := SystemNetworkPolicyToThirdParty(kvp)
	res := thirdparty.SystemNetworkPolicy{}
	req := c.tprClient.Post().
		Resource(SystemNetworkPolicyResourceName).
		Namespace("kube-system").
		Body(tpr)
	err := req.Do().Into(&res)
	if err != nil {
		return nil, K8sErrorToCalico(err, kvp.Key)
	}
	kvp.Revision = res.Metadata.ResourceVersion
	return kvp, nil
}

// Update implements the Update method for System Network Policies (exposed
// through the libcalico-go API as standard Policy resources)
func (c *snpClient) Update(kvp *model.KVPair) (*model.KVPair, error) {
	log.WithField("KV", kvp).Debug("Performing System Network Policy Update")
	tpr := SystemNetworkPolicyToThirdParty(kvp)
	res := thirdparty.SystemNetworkPolicy{}
	req := c.tprClient.Put().
		Resource(SystemNetworkPolicyResourceName).
		Namespace("kube-system").
		Body(tpr).
		Name(tpr.Metadata.Name)
	err := req.Do().Into(&res)
	if err != nil {
		return nil, K8sErrorToCalico(err, kvp.Key)
	}
	kvp.Revision = tpr.Metadata.ResourceVersion
	return kvp, nil
}

// Apply implements the Apply method for System Network Policies (exposed
// through the libcalico-go API as standard Policy resources)
func (c *snpClient) Apply(kvp *model.KVPair) (*model.KVPair, error) {
	log.WithField("KV", kvp).Debug("Performing System Network Policy Apply")
	updated, err := c.Update(kvp)
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			return nil, err
		}

		// It doesn't exist - create it.
		updated, err = c.Create(kvp)
		if err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// Delete implements the Delete method for System Network Policies (exposed
// through the libcalico-go API as standard Policy resources)
func (c *snpClient) Delete(kvp *model.KVPair) error {
	log.WithField("KV", kvp).Debug("Performing System Network Policy Delete")
	result := c.tprClient.Delete().
		Resource(SystemNetworkPolicyResourceName).
		Namespace("kube-system").
		Name(systemNetworkPolicyTPRName(kvp.Key)).
		Do()
	return K8sErrorToCalico(result.Error(), kvp.Key)
}

// Get implements the Get method for System Network Policies (exposed
// through the libcalico-go API as standard Policy resources)
func (c *snpClient) Get(key model.Key) (*model.KVPair, error) {
	log.WithField("Key", key).Debug("Performing System Network Policy Delete")
	tpr := thirdparty.SystemNetworkPolicy{}
	err := c.tprClient.Get().
		Resource(SystemNetworkPolicyResourceName).
		Namespace("kube-system").
		Name(systemNetworkPolicyTPRName(key)).
		Do().Into(&tpr)
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}

	return ThirdPartyToSystemNetworkPolicy(&tpr), nil
}

// List implements the List method for System Network Policies (exposed
// through the libcalico-go API as standard Policy resources)
func (c *snpClient) List(list model.ListInterface) ([]*model.KVPair, error) {
	kvps := []*model.KVPair{}
	l := list.(model.PolicyListOptions)

	// If the Name is specified, k8s will return a single resource
	// rather than a list, so handle this case separately, using our
	// Get method to return the single result.
	if l.Name != "" {
		log.Debug("Performing System Network Policy List with name")
		if kvp, err := c.Get(model.PolicyKey{Name: l.Name}); err == nil {
			kvps = append(kvps, kvp)
		} else {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				return nil, err
			}
		}
		return kvps, nil
	}
	log.Debug("Performing System Network Policy List without name")

	// Since we are not performing an exact Get, Kubernetes will return a list
	// of resources.
	tprs := thirdparty.SystemNetworkPolicyList{}

	// Perform the request.
	err := c.tprClient.Get().
		Resource(SystemNetworkPolicyResourceName).
		Namespace("kube-system").
		Do().Into(&tprs)
	if err != nil {
		// Don't return errors for "not found".  This just
		// means there are no SystemNetworkPolicies, and we should return
		// an empty list.
		if !kerrors.IsNotFound(err) {
			return nil, K8sErrorToCalico(err, l)
		}
	}

	// Convert them to KVPairs.
	for _, tpr := range tprs.Items {
		kvps = append(kvps, ThirdPartyToSystemNetworkPolicy(&tpr))
	}
	return kvps, nil
}

// EnsureInitalized ensures Kubernetes is correctly configured to handle the
// System Network Policy Third Party Resources.
func (c *snpClient) EnsureInitialized() error {
	log.Info("Ensuring System Network Policy ThirdPartyResource exists")
	tpr := extensions.ThirdPartyResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SystemNetworkPolicyTPRName,
			Namespace: "kube-system",
		},
		Description: "Calico System Network Policies",
		Versions:    []extensions.APIVersion{{Name: "v1"}},
	}
	_, err := c.clientSet.Extensions().ThirdPartyResources().Create(&tpr)
	if err != nil {
		// Don't care if it already exists.
		if !kerrors.IsAlreadyExists(err) {
			return K8sErrorToCalico(err, tpr)
		}
	}
	return nil
}

func (c *snpClient) EnsureCalicoNodeInitialized(node string) error {
	return nil
}

func (c *snpClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return nil
}
