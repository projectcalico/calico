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
	"context"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// Action strings - used for context logging.
type action string

const (
	actApply  action = "Apply"
	actCreate action = "Create"
	actUpdate action = "Update"
)

// CustomK8sNodeResourceConverter defines an interface to map between the model and the
// annotation representation of a resource.,
type CustomK8sNodeResourceConverter interface {
	// ListInterfaceToNodeAndName converts the ListInterface to the node name
	// and resource name.
	ListInterfaceToNodeAndName(model.ListInterface) (string, string, error)

	// KeyToNodeAndName converts the Key to the node name and resource name.
	KeyToNodeAndName(model.Key) (string, string, error)

	// NodeAndNameToKey converts the Node name and resource name to a Key.
	NodeAndNameToKey(string, string) (model.Key, error)
}

// CustomK8sNodeResourceClientConfig is the config required for initializing a new
// per-node K8sResourceClient
type CustomK8sNodeResourceClientConfig struct {
	ClientSet    *kubernetes.Clientset
	ResourceType string
	Converter    CustomK8sNodeResourceConverter
	Namespace    string
}

// NewCustomK8sNodeResourceClient creates a new per-node K8sResourceClient.
func NewCustomK8sNodeResourceClient(config CustomK8sNodeResourceClientConfig) K8sResourceClient {
	return &nodeRetryWrapper{
		retryWrapper: &retryWrapper{
			client: &customK8sNodeResourceClient{
				CustomK8sNodeResourceClientConfig: config,
				annotationKeyPrefix:               config.Namespace + "/",
			},
		},
	}
}

// nodeRetryWrapper extends the retryWrapper to include the ExtractResourcesFromNode
// method.
type nodeRetryWrapper struct {
	*retryWrapper
}

// customK8sNodeResourceClient implements the K8sResourceClient interface.  It
// should only be created using newCustomK8sNodeResourceClientConfig since that
// ensures it is wrapped with a retryWrapper.
type customK8sNodeResourceClient struct {
	CustomK8sNodeResourceClientConfig
	annotationKeyPrefix string
}

func (c *customK8sNodeResourceClient) Get(key model.Key) (*model.KVPair, error) {
	logContext := log.WithFields(log.Fields{
		"Key":       key,
		"Resource":  c.ResourceType,
		"Namespace": c.Namespace,
	})
	logContext.Debug("Get per-Node resource")

	// Get the names and the latest Node settings associated with the Key.
	name, node, err := c.getNameAndNodeFromKey(key)
	if err != nil {
		logContext.WithError(err).Info("Failed to get resource")
		return nil, err
	}

	// Extract the resource from the annotations.  It should exist.
	kvps, err := c.extractResourcesFromAnnotation(node, name)
	if err != nil {
		logContext.WithError(err).Error("Failed to get resource: error in data")
		return nil, err
	}
	if len(kvps) != 1 {
		logContext.Warning("Failed to get resource: resource does not exist")
		return nil, errors.ErrorResourceDoesNotExist{Identifier: key}
	}

	return kvps[0], nil
}

func (c *customK8sNodeResourceClient) List(list model.ListInterface) ([]*model.KVPair, string, error) {
	logContext := log.WithFields(log.Fields{
		"ListInterface": list,
		"Resource":      c.ResourceType,
		"Namespace":     c.Namespace,
	})
	logContext.Debug("List per-Node Resources")
	kvps := []*model.KVPair{}

	// Extract the Node and Name from the ListInterface.
	nodeName, resName, err := c.Converter.ListInterfaceToNodeAndName(list)
	if err != nil {
		logContext.WithError(err).Info("Failed to list resources: error in list interface conversion")
		return nil, "", err
	}

	ctx := context.Background()

	// Get a list of the required nodes - which will either be all of them
	// or a specific node.
	var nodes []apiv1.Node
	var rev string
	if nodeName != "" {
		newLogContext := logContext.WithField("NodeName", nodeName)
		node, err := c.ClientSet.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			err = K8sErrorToCalico(err, nodeName)
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				newLogContext.WithError(err).Error("Failed to list resources: unable to query node")
				return nil, "", err
			}
			newLogContext.WithError(err).Warning("Return no results for resource list: node does not exist")
			return kvps, "", nil
		}
		nodes = append(nodes, *node)
		rev = node.GetResourceVersion()
	} else {
		nodeList, err := c.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			logContext.WithError(err).Info("Failed to list resources: unable to list Nodes")
			return nil, "", K8sErrorToCalico(err, nodeName)
		}
		nodes = nodeList.Items
		rev = nodeList.GetResourceVersion()
	}

	// Loop through each of the nodes and extract the required data.
	for _, node := range nodes {
		nodeKVPs, err := c.extractResourcesFromAnnotation(&node, resName)
		if err != nil {
			logContext.WithField("NodeName", node.GetName()).WithError(err).Error("Error listing resources: error in data")
		}
		kvps = append(kvps, nodeKVPs...)
	}

	return kvps, rev, nil
}

// getNameAndNodeFromKey extracts the resource name from the key
// and gets the Node resource from the Kubernetes API.
// Returns: the resource name, the Node resource.
func (c *customK8sNodeResourceClient) getNameAndNodeFromKey(key model.Key) (string, *apiv1.Node, error) {
	logContext := log.WithFields(log.Fields{
		"Key":       key,
		"Resource":  c.ResourceType,
		"Namespace": c.Namespace,
	})
	logContext.Debug("Extract node and resource info from Key")

	// Get the node and resource name.
	nodeName, resName, err := c.Converter.KeyToNodeAndName(key)
	if err != nil {
		logContext.WithError(err).Info("Error converting Key to Node and Resource name.")
		return "", nil, err
	}

	// Get the current node settings.
	node, err := c.ClientSet.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		logContext.WithError(err).Info("Error getting Node configuration")
		return "", nil, K8sErrorToCalico(err, key)
	}

	return resName, node, nil
}

// nameToAnnotationKey converts the resource name to the annotations key.
func (c *customK8sNodeResourceClient) nameToAnnotationKey(name string) string {
	return c.annotationKeyPrefix + name
}

// annotationKeyToName converts the annotations key to a resource name, or returns
// and empty string if the annotation key does not represent a resource.
func (c *customK8sNodeResourceClient) annotationKeyToName(key string) string {
	if strings.HasPrefix(key, c.annotationKeyPrefix) {
		return key[len(c.annotationKeyPrefix):]
	}
	return ""
}

// applyResourceToAnnotation applies the per-Node resource to the Node annotation.
func (c *customK8sNodeResourceClient) applyResourceToAnnotation(node *apiv1.Node, resName string, kvp *model.KVPair, action action) (*model.KVPair, error) {
	logContext := log.WithFields(log.Fields{
		"Value":     kvp.Value,
		"Resource":  c.ResourceType,
		"Action":    action,
		"Namespace": c.Namespace,
	})

	logContext.Debug("Updating value in annotation")
	data, err := model.SerializeValue(kvp)
	if err != nil {
		logContext.Error("Unable to convert value for annotation")
		return nil, err
	}
	if node.Annotations == nil {
		node.Annotations = map[string]string{}
	}
	node.Annotations[c.nameToAnnotationKey(resName)] = string(data)

	// Update the Node resource.
	node, err = c.ClientSet.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{})
	if err != nil {
		// Failed to update the Node.  Just log info and perform a retry.  The retryWrapper will
		// log Error if this continues to fail.
		logContext.WithError(err).Warning("Error updating Kubernetes Node")
		err = K8sErrorToCalico(err, kvp.Key)

		// If this is an update conflict, indicate to the retryWrapper
		// that we can retry the action.
		if _, ok := err.(errors.ErrorResourceUpdateConflict); ok {
			err = retryError{err: err}
		}
		return nil, err
	}

	// Return the Key and Value with updated Revision information.
	return &model.KVPair{
		Key:      kvp.Key,
		Value:    kvp.Value,
		Revision: node.GetObjectMeta().GetResourceVersion(),
	}, nil
}

// extractResourcesFromAnnotation queries the current Kubernetes Node resource
// and parses the per-node resource entries configured in the annotations.
// Returns the Node resource configuration and the slice of parsed resources.
func (c *customK8sNodeResourceClient) extractResourcesFromAnnotation(node *apiv1.Node, name string) ([]*model.KVPair, error) {
	logContext := log.WithFields(log.Fields{
		"ResourceType": name,
		"Resource":     c.ResourceType,
		"Namespace":    c.Namespace,
	})
	logContext.Debug("Extract node and resource info from Key")

	// Extract the resource entries from the annotation.  We do this either by
	// extracting the requested entry if it exists, or by iterating through each
	// annotation and checking if it corresponds to a resource.
	resStrings := make(map[string]string, 0)
	resNames := []string{}
	if name != "" {
		ak := c.nameToAnnotationKey(name)
		if v, ok := node.Annotations[ak]; ok {
			resStrings[name] = v
			resNames = append(resNames, name)
		}
	} else {
		for ak, v := range node.Annotations {
			if n := c.annotationKeyToName(ak); n != "" {
				resStrings[n] = v
				resNames = append(resNames, n)
			}
		}
	}

	// Sort the resource names to ensure the KVPairs are ordered.
	sort.Strings(resNames)

	// Process each entry in name order and add to the return set of KVPairs.
	// Use the node revision as the revision of each entry.  If we hit an error
	// unmarshalling then return the error if we are querying an exact entry, but
	// swallow the error if we are listing multiple (otherwise a single bad entry
	// would prevent all resources being listed).
	kvps := []*model.KVPair{}
	for _, resName := range resNames {
		key, err := c.Converter.NodeAndNameToKey(node.GetName(), resName)
		if err != nil {
			logContext.WithField("ResourceType", resName).WithError(err).Error("Error unmarshalling key")
			if name != "" {
				return nil, err
			}
			continue
		}

		value, err := model.ParseValue(key, []byte(resStrings[resName]))
		if err != nil {
			logContext.WithField("ResourceType", resName).WithError(err).Error("Error unmarshalling value")
			if name != "" {
				return nil, err
			}
			continue
		}
		kvp := &model.KVPair{
			Key:      key,
			Value:    value,
			Revision: node.GetResourceVersion(),
		}
		kvps = append(kvps, kvp)
	}

	return kvps, nil
}

// ExtractResourcesFromNode returns the resources stored in the Node configuration.
//
// This convenience method is expected to be removed in a future libcalico-go release.
func (c *customK8sNodeResourceClient) ExtractResourcesFromNode(node *apiv1.Node) ([]*model.KVPair, error) {
	return c.extractResourcesFromAnnotation(node, "")
}
