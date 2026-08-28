// Copyright (c) 2020, 2023 Tigera, Inc. All rights reserved.

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

package elasticsearch

import (
	"fmt"
	"strconv"

	"github.com/pkg/errors"
	"github.com/tigera/operator/pkg/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ClusterConfigConfigMapName = "tigera-secure-elasticsearch"
)

func NewClusterConfig(clusterName string, replicas int, shards int, flowShards int) *ClusterConfig {
	return &ClusterConfig{
		clusterName: clusterName,
		replicas:    replicas,
		shards:      shards,
		flowShards:  flowShards,
	}
}

func NewClusterConfigFromConfigMap(configMap *corev1.ConfigMap) (*ClusterConfig, error) {
	var replicas, shards, flowShards int
	var err error

	if configMap.Data["clusterName"] == "" {
		return nil, fmt.Errorf("'clusterName' is not set")
	}

	if configMap.Data["replicas"] == "" {
		return nil, fmt.Errorf("'replicas' is not set")
	} else {
		if replicas, err = strconv.Atoi(configMap.Data["replicas"]); err != nil {
			return nil, errors.Wrap(err, "'replicas' must be an integer")
		}
	}

	if configMap.Data["shards"] == "" {
		return nil, fmt.Errorf("'shards' is not set")
	} else {
		if shards, err = strconv.Atoi(configMap.Data["shards"]); err != nil {
			return nil, errors.Wrap(err, "'shards' must be an integer")
		}
	}

	if configMap.Data["flowShards"] == "" {
		return nil, fmt.Errorf("'flowShards' is not set")
	} else {
		if flowShards, err = strconv.Atoi(configMap.Data["flowShards"]); err != nil {
			return nil, errors.Wrap(err, "'flowShards' must be an integer")
		}
	}

	return NewClusterConfig(configMap.Data["clusterName"], replicas, shards, flowShards), nil
}

type ClusterConfig struct {
	clusterName string
	replicas    int
	shards      int
	flowShards  int
}

func (c ClusterConfig) ClusterName() string {
	return c.clusterName
}

func (c ClusterConfig) Replicas() int {
	return c.replicas
}

func (c ClusterConfig) Shards() int {
	return c.shards
}

func (c ClusterConfig) FlowShards() int {
	return c.flowShards
}

func (c ClusterConfig) ConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ClusterConfigConfigMapName,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string]string{
			"clusterName": c.clusterName,
			"replicas":    strconv.Itoa(c.replicas),
			"shards":      strconv.Itoa(c.shards),
			"flowShards":  strconv.Itoa(c.flowShards),
		},
	}
}
