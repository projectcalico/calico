// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package istio

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	//go:embed base.tgz
	baseTgz []byte
	//go:embed istiod.tgz
	istiodTgz []byte
	//go:embed cni.tgz
	cniTgz []byte
	//go:embed ztunnel.tgz
	ztunnelTgz []byte
)

type IstioResources struct {
	CRDs    []client.Object
	Base    []client.Object
	Istiod  []client.Object
	CNI     []client.Object
	ZTunnel []client.Object

	IstiodDeployment              *appsv1.Deployment
	CNIDaemonSet                  *appsv1.DaemonSet
	ZTunnelDaemonSet              *appsv1.DaemonSet
	IstioSidecarInjectorConfigMap *corev1.ConfigMap
}

type ResourceOpts struct {
	Namespace   string
	ReleaseName string

	IstiodDeploymentName      string
	IstioCNIDaemonSetName     string
	IstioZTunnelDaemonSetName string

	BaseOpts     BaseOpts
	IstiodOpts   IstiodOpts
	IstioCNIOpts IstioCNIOpts
	ZTunnelOpts  ZTunnelOpts
}

// GetResources returns istio-chart generated templates
func (r *ResourceOpts) GetResources(scheme *runtime.Scheme) (*IstioResources, error) {
	var crds []client.Object

	actionConfig := new(action.Configuration)

	baseChart, err := loader.LoadArchive(bytes.NewReader(baseTgz))
	if err != nil {
		return nil, fmt.Errorf("failed to load istio-base chart: %w", err)
	}
	istiodChart, err := loader.LoadArchive(bytes.NewReader(istiodTgz))
	if err != nil {
		return nil, fmt.Errorf("failed to load istiod chart: %w", err)
	}
	cniChart, err := loader.LoadArchive(bytes.NewReader(cniTgz))
	if err != nil {
		return nil, fmt.Errorf("failed to load istio-cni chart: %w", err)
	}
	ztunnelChart, err := loader.LoadArchive(bytes.NewReader(ztunnelTgz))
	if err != nil {
		return nil, fmt.Errorf("failed to load ztunnel chart: %w", err)
	}

	client := action.NewInstall(actionConfig)
	client.DryRun = true
	client.ClientOnly = true
	client.Namespace = r.Namespace
	client.ReleaseName = r.ReleaseName

	res := &IstioResources{}
	baseOptions, _ := toMap(r.BaseOpts)
	rel, err := client.Run(baseChart, baseOptions)
	if err != nil {
		return nil, err
	}
	crds, res.Base, err = r.parseManifest(scheme, rel.Manifest, res)
	if err != nil {
		return nil, err
	}
	res.CRDs = append(res.CRDs, crds...)

	istiodOptions, _ := toMap(r.IstiodOpts)
	rel, err = client.Run(istiodChart, istiodOptions)
	if err != nil {
		return nil, err
	}
	crds, res.Istiod, err = r.parseManifest(scheme, rel.Manifest, res)
	if err != nil {
		return nil, err
	}
	res.CRDs = append(res.CRDs, crds...)

	cniOptions, _ := toMap(r.IstioCNIOpts)
	rel, err = client.Run(cniChart, cniOptions)
	if err != nil {
		return nil, err
	}
	crds, res.CNI, err = r.parseManifest(scheme, rel.Manifest, res)
	if err != nil {
		return nil, err
	}
	res.CRDs = append(res.CRDs, crds...)

	ztunnelOptions, _ := toMap(r.ZTunnelOpts)
	rel, err = client.Run(ztunnelChart, ztunnelOptions)
	if err != nil {
		return nil, err
	}
	crds, res.ZTunnel, err = r.parseManifest(scheme, rel.Manifest, res)
	if err != nil {
		return nil, err
	}
	res.CRDs = append(res.CRDs, crds...)

	return res, nil
}

func (r *ResourceOpts) parseManifest(scheme *runtime.Scheme, manifest string, istRes *IstioResources) (crds, objs []client.Object, err error) {
	codecs := serializer.NewCodecFactory(scheme)
	universalDeserializer := codecs.UniversalDeserializer()

	// Use streaming YAML decoder to handle multiple documents
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(manifest)), 4096)

	for {
		var rawObj runtime.RawExtension
		if err := decoder.Decode(&rawObj); err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, fmt.Errorf("error decoding manifest document: %w", err)
		}

		if len(rawObj.Raw) == 0 {
			continue
		}

		obj, _, err := universalDeserializer.Decode(rawObj.Raw, nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("error deserializing object: %w", err)
		}

		clientObj, ok := obj.(client.Object)
		if !ok {
			return nil, nil, fmt.Errorf("missing scheme or object does not implement client.Object: %T", obj)
		}

		switch typedObj := clientObj.(type) {
		case *apiextv1.CustomResourceDefinition:
			crds = append(crds, typedObj)

		case *corev1.ConfigMap:
			switch typedObj.Name {
			case "values":
				break
			case IstioSidecarInjectorConfigMapName:
				istRes.IstioSidecarInjectorConfigMap = typedObj
			}
			objs = append(objs, typedObj)

		case *appsv1.Deployment:
			objs = append(objs, typedObj)
			if r.IstiodDeploymentName != "" && typedObj.Name == r.IstiodDeploymentName {
				istRes.IstiodDeployment = typedObj
			}

		case *appsv1.DaemonSet:
			objs = append(objs, typedObj)
			switch typedObj.Name {
			case r.IstioCNIDaemonSetName:
				istRes.CNIDaemonSet = typedObj
			case r.IstioZTunnelDaemonSetName:
				istRes.ZTunnelDaemonSet = typedObj
			}

		default:
			objs = append(objs, typedObj)
		}
	}

	return crds, objs, nil
}
