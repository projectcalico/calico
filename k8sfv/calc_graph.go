// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package main

import (
	"sync"

	log "github.com/Sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/apis/meta/v1"
)

func rotateLabels(clientset *kubernetes.Clientset, nsPrefix string) error {
	nsMaturity := map[string]string{}
	maturities := []string{"production", "test", "staging", "experimental"}

	// Create namespaces.
	for _, area := range []string{"1", "2", "3", "4", "5"} {
		for _, maturity := range maturities {
			name := nsPrefix + area + "-" + maturity
			createNamespace(
				clientset,
				name,
				map[string]string{
					"area":     "area" + area,
					"maturity": maturity,
				},
			)
			nsMaturity[name] = maturity
		}
	}

	d := NewDeployment(49, true)

	// Create pods.
	waiter := sync.WaitGroup{}
	waiter.Add(len(nsMaturity))
	for nsName, _ := range nsMaturity {
		nsName := nsName
		go func() {
			for _, role := range []string{"1", "2", "3", "4", "5"} {
				for _, instance := range []string{"1", "2", "3", "4", "5"} {
					for _, ha := range []string{"active", "backup"} {
						createPod(
							clientset,
							d,
							nsName,
							podSpec{labels: map[string]string{
								"role":     "role" + role,
								"instance": "instance" + instance,
								"ha":       ha,
							}},
						)
					}
				}
			}
			waiter.Done()
		}()
	}
	waiter.Wait()

	// Rotate the namespace labels.
	changeFrom := append(maturities, "out-of-service")
	changeTo := append([]string{"out-of-service"}, maturities...)
	for ii := range changeFrom {
		log.Infof("Change all '%s' namespaces to '%s'", changeFrom[ii], changeTo[ii])
		for nsName, maturity := range nsMaturity {
			if maturity == changeFrom[ii] {
				nsMaturity[nsName] = changeTo[ii]
				ns_in, err := clientset.Namespaces().Get(nsName, v1.GetOptions{})
				log.WithField("ns_in", ns_in).Debug("Namespace retrieved")
				if err != nil {
					panic(err)
				}
				ns_in.ObjectMeta.Labels["maturity"] = changeTo[ii]
				ns_out, err := clientset.Namespaces().Update(ns_in)
				log.WithField("ns_out", ns_out).Debug("Updated namespace")
			}
		}
	}
	return nil
}
