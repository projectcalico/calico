// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
//
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

package proxy

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/felix/bpf/proxy/maps"
)

// StartKubeProxy start a new kube-proxy if there was no error
func StartKubeProxy(k8sClientSet *kubernetes.Clientset, hostname string, opts ...Option) error {
	natMap := maps.NATMap()
	err := natMap.EnsureExists()
	if err != nil {
		return errors.Errorf("failed to create NAT map: %s", err)
	}
	backendMap := maps.BackendMap()
	err = backendMap.EnsureExists()
	if err != nil {
		return errors.Errorf("failed to create NAT backend map: %s", err)
	}

	syncer, err := NewSyncer(nil, natMap, backendMap)
	if err != nil {
		return errors.WithMessage(err, "new bpf syncer")
	}

	_, err = New(k8sClientSet, syncer, hostname, opts...)
	if err != nil {
		return errors.WithMessage(err, "new proxy")
	}

	log.Infof("kube-proxy started, hostname=%q", hostname)

	return nil
}
