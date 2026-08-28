// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package convert

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CheckedDaemonSet keeps track of which fields have been 'checked' by handlers.
// This is done so that at the end of the migration, any 'unchecked' fields can be reported
// and errored.
type CheckedDaemonSet struct {
	appsv1.DaemonSet

	checkedVars map[string]checkedFields
}

type checkedFields struct {
	envVars map[string]bool
}

// uncheckedVars returns a list of all environment variables which
// were not checked by handlers.
func (r *CheckedDaemonSet) uncheckedVars() []string {
	unchecked := []string{}

	for _, t := range r.Spec.Template.Spec.Containers {
		for _, v := range t.Env {
			if _, ok := r.checkedVars[t.Name].envVars[v.Name]; !ok {
				unchecked = append(unchecked, t.Name+"/"+v.Name)
			}
		}
	}

	for _, t := range r.Spec.Template.Spec.InitContainers {
		for _, v := range t.Env {
			if _, ok := r.checkedVars[t.Name].envVars[v.Name]; !ok {
				unchecked = append(unchecked, t.Name+"/"+v.Name)
			}
		}
	}

	return unchecked
}

// getEnv gets the value of an environment variable and marks that it has been checked.
func (r *CheckedDaemonSet) getEnv(ctx context.Context, client client.Client, container string, key string) (*string, error) {
	v, err := getEnv(ctx, client, r.Spec.Template.Spec, ComponentCalicoNode, container, key)
	if err != nil {
		return nil, err
	}
	r.ignoreEnv(container, key)

	return v, nil
}

// assertEnv gets the value of an environment variable, marks that it has been checked, and, if it is set, compares it to an expectedValue
// returning an error if it does not match.
func (r *CheckedDaemonSet) assertEnv(ctx context.Context, client client.Client, container, key, expectedValue string) error {
	if err := assertEnv(ctx, client, r.Spec.Template.Spec, ComponentCalicoNode, container, key, expectedValue); err != nil {
		return err
	}
	r.ignoreEnv(container, key)
	return nil
}

// assertEnv gets the value of an environment variable, marks that it has been checked, and, if it is set, compares it to an expectedValue
// returning an error if it does not match.
func assertEnv(ctx context.Context, client client.Client, spec corev1.PodSpec, component, container, key, expectedValue string) error {
	value, err := getEnv(ctx, client, spec, component, container, key)
	if err != nil {
		return err
	}

	if value != nil && strings.ToLower(*value) != expectedValue {
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("%s=%s is not supported", key, *value),
			component: component,
			fix:       fmt.Sprintf("remove the %s env var or set it to '%s'", key, expectedValue),
		}
	}

	return nil
}

// assertEnvIsSet gets the value of an environment variable, marks that it has been checked, and compares it to an expectedValue,
// returning an error if it does not match.
func (r *CheckedDaemonSet) assertEnvIsSet(ctx context.Context, client client.Client, container, key, expectedValue string) error {
	if err := assertEnvIsSet(ctx, client, r.Spec.Template.Spec, ComponentCalicoNode, container, key, expectedValue); err != nil {
		return err
	}
	r.ignoreEnv(container, key)
	return nil
}

// assertEnv gets the value of an environment variable, marks that it has been checked, and compares it to an expectedValue,
// returning an error if it does not match.
func assertEnvIsSet(ctx context.Context, client client.Client, spec corev1.PodSpec, component, container, key, expectedValue string) error {
	value, err := getEnv(ctx, client, spec, component, container, key)
	if err != nil {
		return err
	}

	if value == nil || strings.ToLower(*value) != expectedValue {
		v := "<undefined>"
		if value != nil {
			v = *value
		}
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("%s=%s is not supported", key, v),
			component: component,
			fix:       fmt.Sprintf("set the %s env var to '%s'", key, expectedValue),
		}
	}

	return nil
}

// getEnvVar returns a kubernetes envVar and marks that it has been checked.
func (r *CheckedDaemonSet) getEnvVar(container string, key string) (*corev1.EnvVar, error) {
	c := getContainer(r.Spec.Template.Spec, container)
	if c == nil {
		return nil, ErrIncompatibleCluster{
			err:       fmt.Sprintf("couldn't find %s container in daemonset", container),
			component: ComponentCalicoNode,
			fix:       fmt.Sprintf("restore the %s container if you've renamed or removed it", container),
		}
	}
	r.ignoreEnv(container, key)

	for _, e := range c.Env {
		if e.Name == key {
			return &e, nil
		}
	}
	return nil, nil
}

// ignoreEnv marks an environment variable as checked so that the migrator
// will not raise an error for it.
func (r *CheckedDaemonSet) ignoreEnv(container, key string) {
	if _, ok := r.checkedVars[container]; !ok {
		r.checkedVars[container] = checkedFields{
			map[string]bool{},
		}
	}
	r.checkedVars[container].envVars[key] = true
}

// getEnv gets the value of an environment variable.
func getEnv(ctx context.Context, client client.Client, pts corev1.PodSpec, component, container, key string) (*string, error) {
	c := getContainer(pts, container)
	if c == nil {
		return nil, ErrIncompatibleCluster{
			err:       fmt.Sprintf("couldn't find container '%s' in %s", container, component),
			component: component,
			fix:       fmt.Sprintf("restore the %s container if you've renamed or removed it", container),
		}
	}

	for _, e := range c.Env {
		if e.Name == key {
			if e.ValueFrom == nil {
				return &e.Value, nil
			}
			if e.ValueFrom.ConfigMapKeyRef != nil {
				cm := corev1.ConfigMap{}
				err := client.Get(ctx, types.NamespacedName{
					Name:      e.ValueFrom.ConfigMapKeyRef.Name,
					Namespace: "kube-system",
				}, &cm)
				if err != nil {
					return nil, err
				}
				v := cm.Data[e.ValueFrom.ConfigMapKeyRef.Key]
				return &v, nil
			}

			return nil, ErrIncompatibleCluster{
				err:       fmt.Sprintf("failed to read %s/%s: only configMapRef & explicit values supported for env vars at this time", container, key),
				component: "",
				fix:       fmt.Sprintf("adjust %s to be an explicit value or configMapRef", key),
			}
		}
	}
	return nil, nil
}
