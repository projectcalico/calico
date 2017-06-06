// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

func NewIPPools(c *kubernetes.Clientset, r *rest.RESTClient) api.Client {
	return &ipPoolsClient{
		clientSet: c,
		tprClient: r,
	}
}

func ListIPPoolsWithResourceVersion(client api.Client, list model.ListInterface) ([]*model.KVPair, string, error) {
	c := client.(*ipPoolsClient)
	return c.listWithResourceVersion(list)
}

// Implements the api.Client interface for pools.
type ipPoolsClient struct {
	clientSet *kubernetes.Clientset
	tprClient *rest.RESTClient
}

func (c *ipPoolsClient) Create(kvp *model.KVPair) (*model.KVPair, error) {
	tpr := IPPoolToThirdParty(kvp)
	res := thirdparty.IpPool{}
	req := c.tprClient.Post().
		Resource("ippools").
		Namespace("kube-system").
		Body(tpr)
	err := req.Do().Into(&res)
	if err != nil {
		return nil, K8sErrorToCalico(err, kvp.Key)
	}
	kvp.Revision = res.Metadata.ResourceVersion
	return kvp, nil
}

func (c *ipPoolsClient) Update(kvp *model.KVPair) (*model.KVPair, error) {
	tpr := IPPoolToThirdParty(kvp)
	res := thirdparty.IpPool{}
	req := c.tprClient.Put().
		Resource("ippools").
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

func (c *ipPoolsClient) Apply(kvp *model.KVPair) (*model.KVPair, error) {
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

func (c *ipPoolsClient) Delete(kvp *model.KVPair) error {
	result := c.tprClient.Delete().
		Resource("ippools").
		Namespace("kube-system").
		Name(ipPoolTprName(kvp.Key.(model.IPPoolKey))).
		Do()
	return K8sErrorToCalico(result.Error(), kvp.Key)
}

func (c *ipPoolsClient) Get(key model.Key) (*model.KVPair, error) {
	tpr := thirdparty.IpPool{}
	err := c.tprClient.Get().
		Resource("ippools").
		Namespace("kube-system").
		Name(ipPoolTprName(key.(model.IPPoolKey))).
		Do().Into(&tpr)
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}

	return ThirdPartyToIPPool(&tpr), nil
}

func (c *ipPoolsClient) List(list model.ListInterface) ([]*model.KVPair, error) {
	kvps, _, err := c.listWithResourceVersion(list)
	return kvps, err
}

func (c *ipPoolsClient) listWithResourceVersion(list model.ListInterface) ([]*model.KVPair, string, error) {
	kvps := []*model.KVPair{}
	l := list.(model.IPPoolListOptions)
	resourceVersion := ""

	// If the CIDR is specified, k8s will return a single resource
	// rather than a list, so handle this case separately, using our
	// Get method to return the single result.
	if l.CIDR.IP != nil {
		log.Info("Performing IP pool List with name")
		if kvp, err := c.Get(model.IPPoolKey{CIDR: l.CIDR}); err == nil {
			kvps = append(kvps, kvp)
			resourceVersion = kvp.Revision.(string)
		} else {
			if !kerrors.IsNotFound(err) {
				return nil, resourceVersion, K8sErrorToCalico(err, l)
			}
		}
		return kvps, resourceVersion, nil
	}

	// Since are not performing an exact Get, Kubernetes will return a list
	// of resources.
	tprs := thirdparty.IpPoolList{}

	// Perform the request.
	err := c.tprClient.Get().
		Resource("ippools").
		Namespace("kube-system").
		Do().Into(&tprs)
	if err != nil {
		// Don't return errors for "not found".  This just
		// means there are no IPPools, and we should return
		// an empty list.
		if !kerrors.IsNotFound(err) {
			return nil, resourceVersion, K8sErrorToCalico(err, l)
		}
	}
	resourceVersion = tprs.Metadata.ResourceVersion

	// Convert them to KVPairs.
	for _, tpr := range tprs.Items {
		kvps = append(kvps, ThirdPartyToIPPool(&tpr))
	}
	return kvps, resourceVersion, nil
}

func (c *ipPoolsClient) EnsureInitialized() error {
	log.Info("Ensuring IP Pool ThirdPartyResource exists")
	tpr := extensions.ThirdPartyResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ip-pool.projectcalico.org",
			Namespace: "kube-system",
		},
		Description: "Calico IP Pools",
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

func (c *ipPoolsClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return nil
}

func (c *ipPoolsClient) EnsureCalicoNodeInitialized(node string) error {
	return nil
}
