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
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	apiextenv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml" // gopkg.in/yaml.v2 didn't parse all the fields but this package did

	"github.com/go-logr/logr"
	opv1 "github.com/tigera/operator/api/v1"
)

var (

	//go:embed calico
	calicoCRDFiles embed.FS
	//go:embed enterprise
	enterpriseCRDFiles embed.FS
	//go:embed operator/*
	operatorCRDFiles embed.FS

	calicoOprtrCRDsRe *regexp.Regexp

	// We cache these CRDs because to generate the calico and enterprise takes
	// approximately 40ms, with the caching 1ms.
	lock           sync.Mutex
	calicoCRDs     []*apiextenv1.CustomResourceDefinition
	enterpriseCRDs []*apiextenv1.CustomResourceDefinition
)

func init() {
	calicoCRDNames := []string{"installation", "apiserver", "gatewayapi", "imageset", "tigerastatus", "whisker", "goldmane", "managementclusterconnection", "istio"}
	calicoOprtrCRDsRe = regexp.MustCompile(fmt.Sprintf("(%s)", strings.Join(calicoCRDNames, "|")))
}

func getCalicoCRDSource(v3 bool) map[string][]byte {
	ret := map[string][]byte{}
	dir := "calico/v1.crd.projectcalico.org"
	if v3 {
		dir = "calico/v3.projectcalico.org"
	}
	entries, err := calicoCRDFiles.ReadDir(dir)
	if err != nil {
		panic(fmt.Sprintf("Failed to read Calico CRDs: %v", err))
	}

	for _, entry := range entries {
		b, err := calicoCRDFiles.ReadFile(path.Join(dir, entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("Failed to read Calico CRD %s: %v", entry.Name(), err))
		}

		crds := bytes.Split(b, []byte("\n---"))
		for i, crd := range crds {
			ret[fmt.Sprintf("%s_%d", entry.Name(), i)] = crd
		}
	}

	return ret
}

func getEnterpriseCRDSource(v3 bool) map[string][]byte {
	ret := map[string][]byte{}
	dir := "enterprise/v1.crd.projectcalico.org"
	if v3 {
		dir = "enterprise/v3.projectcalico.org"
	}
	entries, err := enterpriseCRDFiles.ReadDir(dir)
	if err != nil {
		panic(fmt.Sprintf("Failed to read Enterprise CRDs: %v", err))
	}

	// Determine paths of each file to parse, loading all of the files discovered in
	// the Calico CRD directory plus the ECK CRD bundle file.
	files := map[string]string{}
	for _, entry := range entries {
		files[entry.Name()] = path.Join(dir, entry.Name())
	}
	files["01-crd-eck-bundle.yaml"] = "enterprise/01-crd-eck-bundle.yaml"

	for name, path := range files {
		b, err := enterpriseCRDFiles.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("Failed to read Enterprise CRD %s: %v", name, err))
		}

		crds := bytes.Split(b, []byte("\n---"))
		for i, crd := range crds {
			ret[fmt.Sprintf("%s_%d", name, i)] = crd
		}
	}
	return ret
}

func getK8sPolicyCRDSource(variant opv1.ProductVariant) map[string][]byte {
	ret := map[string][]byte{}
	var fs embed.FS
	var dir string
	if variant == opv1.Calico {
		fs = calicoCRDFiles
		dir = "calico/policy.networking.k8s.io"
	} else {
		fs = enterpriseCRDFiles
		dir = "enterprise/policy.networking.k8s.io"
	}
	entries, err := fs.ReadDir(dir)
	if err != nil {
		panic(fmt.Sprintf("Failed to read K8s policy CRDs: %v", err))
	}

	for _, entry := range entries {
		b, err := fs.ReadFile(path.Join(dir, entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("Failed to read K8s policy CRD %s: %v", entry.Name(), err))
		}

		crds := bytes.Split(b, []byte("\n---"))
		for i, crd := range crds {
			ret[fmt.Sprintf("%s_%d", entry.Name(), i)] = crd
		}
	}

	return ret
}

// getApplicationLayerCRDSource returns the applicationlayer.projectcalico.org CRDs
// (the gateway WAF kinds). This is a distinct, CRD-only API group that is not served
// by the aggregated apiserver and has a single v3 schema, so - unlike the
// projectcalico.org datastore CRDs - it is installed in both v1-CRD and v3-CRD modes.
// Enterprise only.
func getApplicationLayerCRDSource() map[string][]byte {
	ret := map[string][]byte{}
	dir := "enterprise/applicationlayer.projectcalico.org"
	entries, err := enterpriseCRDFiles.ReadDir(dir)
	if err != nil {
		panic(fmt.Sprintf("Failed to read ApplicationLayer CRDs: %v", err))
	}

	for _, entry := range entries {
		b, err := enterpriseCRDFiles.ReadFile(path.Join(dir, entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("Failed to read ApplicationLayer CRD %s: %v", entry.Name(), err))
		}

		crds := bytes.Split(b, []byte("\n---"))
		for i, crd := range crds {
			ret[fmt.Sprintf("%s_%d", entry.Name(), i)] = crd
		}
	}

	return ret
}

func getOperatorCRDSource(variant opv1.ProductVariant) map[string][]byte {
	ret := map[string][]byte{}
	entries, err := operatorCRDFiles.ReadDir("operator")
	if err != nil {
		panic(fmt.Sprintf("Failed to read Operator CRDs: %v", err))
	}

	for _, entry := range entries {
		if variant == opv1.Calico {
			if !calicoOprtrCRDsRe.MatchString(entry.Name()) {
				continue
			}
		}

		b, err := operatorCRDFiles.ReadFile(path.Join("operator", entry.Name()))
		if err != nil {
			panic(fmt.Sprintf("Failed to read Operator CRD %s: %v", entry.Name(), err))
		}

		crds := bytes.Split(b, []byte("\n---"))
		for i, crd := range crds {
			ret[fmt.Sprintf("%s_%d", entry.Name(), i)] = crd
		}
	}

	return ret
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
			calicoCRDs = convertYamlsToCRDs(getCalicoCRDSource(v3), getK8sPolicyCRDSource(variant), getOperatorCRDSource(variant))
		}
		crds = calicoCRDs
	} else {
		if len(enterpriseCRDs) == 0 {
			enterpriseCRDs = convertYamlsToCRDs(getEnterpriseCRDSource(v3), getK8sPolicyCRDSource(variant), getOperatorCRDSource(variant), getApplicationLayerCRDSource())
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
