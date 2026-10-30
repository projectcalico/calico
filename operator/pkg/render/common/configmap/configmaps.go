package configmap

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CopyToNamespace returns a new list of config maps generated from the ones given but with the namespace changed to the
// given one.
func CopyToNamespace(ns string, oConfigMaps ...*v1.ConfigMap) []*v1.ConfigMap {
	var configMaps []*v1.ConfigMap
	for _, s := range oConfigMaps {
		x := s.DeepCopy()
		x.ObjectMeta = metav1.ObjectMeta{Name: s.Name, Namespace: ns}

		configMaps = append(configMaps, x)
	}
	return configMaps
}

// ToRuntimeObjects converts the given list of configMaps to a list of client.Objects
func ToRuntimeObjects(configMaps ...*v1.ConfigMap) []client.Object {
	var objs []client.Object
	for _, configMap := range configMaps {
		if configMap == nil {
			continue
		}
		objs = append(objs, configMap)
	}
	return objs
}

// GetEnvVarSource returns an EnvVarSource using the given configmap name and key.
func GetEnvVarSource(cmName string, key string, optional bool) *v1.EnvVarSource {
	var opt *bool
	if optional {
		r := optional
		opt = &r
	}
	return &v1.EnvVarSource{
		ConfigMapKeyRef: &v1.ConfigMapKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: cmName,
			},
			Key:      key,
			Optional: opt,
		},
	}
}
