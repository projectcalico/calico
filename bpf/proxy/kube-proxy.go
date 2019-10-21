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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/felix/bpf/proxy/maps"
)

// StartKubeProxy start a new kube-proxy if there was no error
func StartKubeProxy(hostname string, opts ...Option) error {
	syncer, err := NewSyncer(nil, maps.NATMap(), maps.BackendMap())
	if err != nil {
		return errors.WithMessage(err, "new bpf syncer")
	}

	k8sconf, err := rest.InClusterConfig()
	if err != nil {
		return errors.Errorf("unable to create k8s config: %s", err)
	}
	clientset, err := kubernetes.NewForConfig(k8sconf)
	if err != nil {
		return errors.Errorf("unable to create k8s client set: %s", err)
	}

	_, err = New(clientset, syncer, hostname, opts...)
	if err != nil {
		return errors.WithMessage(err, "new proxy")
	}

	return nil
}
