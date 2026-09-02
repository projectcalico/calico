// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package crds

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	v3crd "github.com/projectcalico/api/config/crd"
	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did

	v1crd "github.com/projectcalico/calico/libcalico-go/config/crd"
	opv1 "github.com/projectcalico/calico/operator/api/v1"
)

// k8sPolicyPrefix marks the policy.networking.k8s.io CRDs, which are generated
// alongside the crd.projectcalico.org ones but installed as their own set.
const k8sPolicyPrefix = "policy.networking.k8s.io_"

var (
	//go:embed operator/*
	operatorCRDFiles embed.FS
	//go:embed calico_operator_crds.txt
	calicoOperatorCRDList string

	calicoOperatorCRDs map[string]bool

	// variantCRDs holds the CRDs a variant installs beyond the operator's own.
	// Enterprise registers its own, which are not built from this repo.
	variantCRDs map[opv1.ProductVariant][]CRDSource

	// We cache these CRDs because to generate the calico and enterprise takes
	// approximately 40ms, with the caching 1ms.
	lock           sync.Mutex
	calicoCRDs     []*apiextenv1.CustomResourceDefinition
	enterpriseCRDs []*apiextenv1.CustomResourceDefinition
)

// CRDSource returns CRD YAML documents keyed by a name unique within the source.
type CRDSource func(v3 bool) map[string][]byte

// RegisterVariantCRDs adds CRDs a variant installs beyond the operator's own.
// Call from an init(): the bootstrap path reads the registry before main runs.
func RegisterVariantCRDs(variant opv1.ProductVariant, sources ...CRDSource) {
	lock.Lock()
	defer lock.Unlock()
	variantCRDs[variant] = append(variantCRDs[variant], sources...)
	calicoCRDs = nil
	enterpriseCRDs = nil
}

func init() {
	variantCRDs = map[opv1.ProductVariant][]CRDSource{}
	calicoOperatorCRDs = map[string]bool{}
	for _, line := range strings.Split(calicoOperatorCRDList, "\n") {
		if name := strings.TrimSpace(line); name != "" && !strings.HasPrefix(name, "#") {
			calicoOperatorCRDs[name] = true
		}
	}
}

// ReadCRDs splits every CRD in files into its YAML documents, for variants whose
// CRDs are generated outside this repo. what names the set in panic messages.
func ReadCRDs(files fs.FS, what string) map[string][]byte {
	return readCRDs(files, what, func(string) bool { return true })
}

// readCRDs splits every file the filter accepts into its YAML documents, keyed by
// file name and document index.
func readCRDs(files fs.FS, what string, keep func(name string) bool) map[string][]byte {
	ret := map[string][]byte{}
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		panic(fmt.Sprintf("Failed to read %s CRDs: %v", what, err))
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yaml") || !keep(entry.Name()) {
			continue
		}

		b, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			panic(fmt.Sprintf("Failed to read %s CRD %s: %v", what, entry.Name(), err))
		}

		docs := bytes.Split(b, []byte("\n---"))
		for i, doc := range docs {
			ret[fmt.Sprintf("%s_%d", entry.Name(), i)] = doc
		}
	}

	return ret
}

// getCalicoCRDSource returns the datastore CRDs, which libcalico-go generates for
// v1 and the api module for v3.
func getCalicoCRDSource(v3 bool) map[string][]byte {
	files, what := v1crd.FS(), "Calico v1"
	if v3 {
		files, what = v3crd.FS(), "Calico v3"
	}
	return readCRDs(files, what, func(name string) bool {
		return !strings.HasPrefix(name, k8sPolicyPrefix)
	})
}

// getK8sPolicyCRDSource returns the policy.networking.k8s.io CRDs, which libcalico-go
// generates beside the v1 datastore CRDs and both CRD modes install.
func getK8sPolicyCRDSource() map[string][]byte {
	return readCRDs(v1crd.FS(), "K8s policy", func(name string) bool {
		return strings.HasPrefix(name, k8sPolicyPrefix)
	})
}

// getOperatorCRDSource returns the operator's own CRDs, trimmed to the set a Calico
// install ships.
func getOperatorCRDSource(variant opv1.ProductVariant) map[string][]byte {
	files, err := fs.Sub(operatorCRDFiles, "operator")
	if err != nil {
		panic(fmt.Sprintf("Failed to read Operator CRDs: %v", err))
	}

	return readCRDs(files, "Operator", func(name string) bool {
		return variant != opv1.Calico || calicoOperatorCRDs[name]
	})
}

func convertYamlsToCRDs(yamls ...map[string][]byte) []*apiextenv1.CustomResourceDefinition {
	crds := []*apiextenv1.CustomResourceDefinition{}
	for _, yamlmap := range yamls {
		for name, yml := range yamlmap {
			crd := &apiextenv1.CustomResourceDefinition{}
			err := yaml.Unmarshal(yml, crd)
			if err != nil {
				panic(fmt.Sprintf("unable to convert %s to CRD: %v", name, err))
			}
			crd.Name = fmt.Sprintf("%s.%s", crd.Spec.Names.Plural, crd.Spec.Group)
			crds = append(crds, crd)
		}
	}

	return crds
}

func GetCRDs(variant opv1.ProductVariant, v3 bool) []*apiextenv1.CustomResourceDefinition {
	lock.Lock()
	defer lock.Unlock()

	var crds []*apiextenv1.CustomResourceDefinition
	if variant == opv1.Calico {
		if len(calicoCRDs) == 0 {
			calicoCRDs = convertYamlsToCRDs(getCalicoCRDSource(v3), getK8sPolicyCRDSource(), getOperatorCRDSource(variant))
		}
		crds = calicoCRDs
	} else {
		if len(enterpriseCRDs) == 0 {
			yamls := []map[string][]byte{getOperatorCRDSource(variant)}
			for _, source := range variantCRDs[variant] {
				yamls = append(yamls, source(v3))
			}
			enterpriseCRDs = convertYamlsToCRDs(yamls...)
		}
		crds = enterpriseCRDs
	}

	// Make a cp of the slice so that when we use the resource to Create or Update
	// our original cp of the definitions are not tainted with a ResourceVersion
	cp := []*apiextenv1.CustomResourceDefinition{}
	for _, crd := range crds {
		// Skip the Tenant CRD - this is only used in Calico Cloud.
		if crd.Name == "tenants.operator.tigera.io" {
			continue
		}
		cp = append(cp, crd.DeepCopy())
	}

	return cp
}

// ToRuntimeObjects converts the given list of CRDs to a list of client.Objects
func ToRuntimeObjects(crds ...*apiextenv1.CustomResourceDefinition) []client.Object {
	var objs []client.Object
	for _, crd := range crds {
		if crd == nil {
			continue
		}
		objs = append(objs, crd)
	}
	return objs
}

// Ensure ensures that the CRDs necessary for bootstrapping exist in the cluster.
// Further reconciliation of the CRDs is handled by the core controller.
func Ensure(c client.Client, variant string, v3 bool, log logr.Logger) error {
	// Ensure Calico CRDs exist, which will allow us to bootstrap.
	for _, crd := range GetCRDs(opv1.ProductVariant(variant), v3) {

		log.Info("ensuring CustomResourceDefinition exists", "name", crd.Name)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := c.Create(ctx, crd); err != nil {
			// Ignore if the CRD already exists
			if !errors.IsAlreadyExists(err) {
				cancel()
				return fmt.Errorf("failed to create CustomResourceDefinition %s: %s", crd.Name, err)
			}
		}
		cancel()
	}
	return nil
}
