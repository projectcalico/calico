// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package helm_test

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
)

// HelmValues is a Go representation of of the values.yaml file for the Calico chart.
type HelmValues struct {
	Datastore string        `yaml:"datastore"`
	Typha     TyphaSettings `yaml:"typha"`
	Etcd      EtcdSettings  `yaml:"etcd"`
}

type TyphaSettings struct {
	Enabled bool `yaml:"enabled"`
}

type EtcdSettings struct {
	Endpoints string `yaml:"endpoints"`
}

var chartPaths = *flag.String("chart-path", "../_includes/charts/calico", "comma separated list of paths to the charts")

// TODO: Add call to kubeval to verify helm resources are valid
func render(values HelmValues) (map[string]runtime.Object, error) {
	allResources := make(map[string]runtime.Object)

	valuesyml, err := yaml.Marshal(values)
	if err != nil {
		return allResources, err
	}

	curdir, err := os.Getwd()
	if err != nil {
		return allResources, err
	}

	f, err := ioutil.TempFile(curdir, "helmfv")
	if err != nil {
		return allResources, err
	}

	defer os.Remove(f.Name())

	_, err = f.Write(valuesyml)
	if err != nil {
		return allResources, err
	}
	if err := f.Close(); err != nil {
		return allResources, err
	}

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	paths := strings.Split(chartPaths, ",")
	for _, path := range paths {
		log.Print(path)
		cmd := exec.Command("helm", "template", "-f", f.Name())
		cmd.Args = append(cmd.Args, path)

		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err = cmd.Run(); err != nil {
			return allResources, fmt.Errorf("error running helm: %s", stderr.String())
		}

		byteObjs := bytes.Split(stdout.Bytes(), []byte("---"))
		for _, byteObj := range byteObjs {

			obj, gvk, err := scheme.Codecs.UniversalDeserializer().Decode(byteObj, nil, nil)
			if err != nil {
				// TODO: Silence the ugly errors for unrendered manifests
				log.Print(err)
				continue
			}

			// Store each object with the key: <Kind>,<Namespace>,<Name>
			// Each object should implement metav1.ObjectMetaAccessor
			oma, ok := obj.(metav1.ObjectMetaAccessor)
			if !ok {
				return allResources, fmt.Errorf("%s does not implement ObjectMetaAccessor", gvk.Kind)
			}

			key := fmt.Sprintf("%s,%s,%s", gvk.Kind, oma.GetObjectMeta().GetNamespace(), oma.GetObjectMeta().GetName())
			allResources[key] = obj
		}
	}

	return allResources, nil
}
