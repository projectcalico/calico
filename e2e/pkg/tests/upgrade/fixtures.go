// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package upgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const fieldManager = "e2e-upgrade"

// Sub returns the fixture directory dir inside an embedded FS. It panics on a
// bad path, which only a typo in a scenario file can cause.
func Sub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(fmt.Sprintf("fixture dir %q: %v", dir, err))
	}
	return sub
}

// ObjRef identifies one applied fixture object.
type ObjRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

// fixtureObjects parses every *.yaml at the fixture root, in lexical order,
// defaulting an empty namespace to the scenario's. Whether that namespace
// sticks depends on the kind's scope, which only the cluster knows.
func (s *Scenario) fixtureObjects() ([]*unstructured.Unstructured, error) {
	if s.Fixtures == nil {
		return nil, nil
	}
	return Objects(s.Fixtures)
}

// Objects parses every *.yaml at the root of fsys, in lexical order. Seed
// steps use it for objects that, unlike fixtures, may be rejected.
func Objects(fsys fs.FS) ([]*unstructured.Unstructured, error) {
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []*unstructured.Unstructured
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for {
			obj := &unstructured.Unstructured{}
			if err := dec.Decode(&obj.Object); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("fixture %s: %w", f, err)
			}
			if len(obj.Object) == 0 {
				continue
			}
			if obj.GetKind() == "" || obj.GetAPIVersion() == "" || obj.GetName() == "" {
				return nil, fmt.Errorf("fixture %s: every object needs apiVersion, kind and metadata.name", f)
			}
			out = append(out, obj)
		}
	}
	return out, nil
}

// applyFixtures server-side applies the fixtures and returns what it applied.
// Cluster-scoped objects outlive the namespace, so they carry the scenario's
// name for cleanup and to avoid colliding with the rest of the suite.
func (s *Scenario) applyFixtures(ctx context.Context, e *Env) ([]ObjRef, error) {
	objs, err := s.fixtureObjects()
	if err != nil {
		return nil, err
	}
	var refs []ObjRef
	for _, o := range objs {
		gvk := o.GroupVersionKind()
		m, err := e.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return refs, fmt.Errorf("fixture %s %s: %w", gvk, o.GetName(), err)
		}
		ri := e.Dynamic.Resource(m.Resource)
		var res interface {
			Apply(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions, ...string) (*unstructured.Unstructured, error)
		} = ri
		if m.Scope.Name() == meta.RESTScopeNameNamespace {
			o.SetNamespace(e.Namespace)
			res = ri.Namespace(e.Namespace)
		} else {
			if !strings.HasPrefix(o.GetName(), "e2e-upgrade-"+s.Name+"-") {
				return refs, fmt.Errorf("cluster-scoped fixture %s %s must be named e2e-upgrade-%s-*", gvk.Kind, o.GetName(), s.Name)
			}
			// A namespace left in the YAML would make cleanup take it for a
			// namespaced object and skip it.
			o.SetNamespace("")
		}
		if _, err := res.Apply(ctx, o.GetName(), o, metav1.ApplyOptions{FieldManager: fieldManager, Force: true}); err != nil {
			return refs, fmt.Errorf("applying fixture %s %s: %w", gvk.Kind, o.GetName(), err)
		}
		refs = append(refs, ObjRef{APIVersion: o.GetAPIVersion(), Kind: gvk.Kind, Namespace: o.GetNamespace(), Name: o.GetName()})
	}
	return refs, nil
}

// Resource maps an object to its resource, and to the scenario namespace when
// the kind is namespaced.
func Resource(e *Env, apiVersion, kind string) (schema.GroupVersionResource, bool, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, false, err
	}
	m, err := e.Mapper.RESTMapping(gv.WithKind(kind).GroupKind(), gv.Version)
	if err != nil {
		return schema.GroupVersionResource{}, false, err
	}
	return m.Resource, m.Scope.Name() == meta.RESTScopeNameNamespace, nil
}

// Create creates obj, in the scenario namespace if its kind is namespaced.
func Create(ctx context.Context, e *Env, obj *unstructured.Unstructured) (ObjRef, error) {
	gvr, namespaced, err := Resource(e, obj.GetAPIVersion(), obj.GetKind())
	if err != nil {
		return ObjRef{}, err
	}
	ref := ObjRef{APIVersion: obj.GetAPIVersion(), Kind: obj.GetKind(), Name: obj.GetName()}
	if namespaced {
		ref.Namespace = e.Namespace
		obj.SetNamespace(e.Namespace)
		_, err = e.Dynamic.Resource(gvr).Namespace(e.Namespace).Create(ctx, obj, metav1.CreateOptions{})
	} else {
		_, err = e.Dynamic.Resource(gvr).Create(ctx, obj, metav1.CreateOptions{})
	}
	return ref, err
}

// deleteClusterScoped removes the cluster-scoped fixtures; the namespace
// delete takes the rest.
func deleteClusterScoped(ctx context.Context, e *Env, refs []ObjRef) error {
	var errs []error
	for _, r := range refs {
		if r.Namespace != "" {
			continue
		}
		gv, err := schema.ParseGroupVersion(r.APIVersion)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		m, err := e.Mapper.RESTMapping(gv.WithKind(r.Kind).GroupKind(), gv.Version)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := e.Dynamic.Resource(m.Resource).Delete(ctx, r.Name, metav1.DeleteOptions{}); err != nil && !isNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// parseTarget splits "svc:<name>:<port>" or "ip:<addr>:<port>".
func parseTarget(t string) (kind, host string, port int, err error) {
	kind, rest, ok := strings.Cut(t, ":")
	if !ok || (kind != "svc" && kind != "ip") {
		return "", "", 0, fmt.Errorf("target %q: want svc:<name>:<port> or ip:<addr>:<port>", t)
	}
	i := strings.LastIndex(rest, ":")
	if i <= 0 {
		return "", "", 0, fmt.Errorf("target %q has no port", t)
	}
	host = rest[:i]
	port, err = strconv.Atoi(rest[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", "", 0, fmt.Errorf("target %q: bad port", t)
	}
	if kind == "ip" && net.ParseIP(strings.Trim(host, "[]")) == nil {
		return "", "", 0, fmt.Errorf("target %q: bad IP", t)
	}
	if kind == "svc" && !dns1123.MatchString(host) {
		return "", "", 0, fmt.Errorf("target %q: bad service name", t)
	}
	return kind, host, port, nil
}
