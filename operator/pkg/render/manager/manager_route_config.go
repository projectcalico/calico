// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package manager

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	voltronRoutesConfigMapName = "voltron-routes"
	voltronRoutesFolderPath    = "/config_maps/voltron-routes"

	configMapFolder = "/config_maps"
	secretsFolder   = "/secrets"

	uiTLSTerminatedRoutesKey              = "uiTLSTermRoutes.json"
	upstreamTunnelTLSTerminatedRoutesKey  = "upTunTLSTermRoutes.json"
	upstreamTunnelTLSPassThroughRoutesKey = "upTunTLSPTRoutes.json"

	routesAnnotationPrefix = "hash.operator.tigera.io/routeconf"
)

// tlsTerminatedRoute is need for the json translation from the TLSTerminatedRoute CR to the json voltron expects to
// see for a route.
type tlsTerminatedRoute struct {
	// Destination is the destination URL
	Destination string `json:"destination"`
	// Path is the path portion of the URL based on which we proxy
	Path string `json:"path"`

	// CABundlePath is where we read the CA bundle from to authenticate the
	// destination (if non-empty)
	CABundlePath string `json:"caBundlePath,omitempty"`
	// PathRegexp, if not nil, checks if Regexp matches the path
	PathRegexp *string `json:"pathRegexp,omitempty"`
	// PathReplace if not nil will be used to replace PathRegexp matches
	PathReplace *string `json:"pathReplace,omitempty"`

	// ClientCertPath and ClientKeyPath can be set for mTLS on the connection
	// from Voltron to the destination.
	ClientCertPath string `json:"clientCertPath,omitempty"`
	ClientKeyPath  string `json:"clientKeyPath,omitempty"`

	Unauthenticated bool `json:"unauthenticated,omitempty"`
}

type tlsTerminatedRouteList []*tlsTerminatedRoute

func (r tlsTerminatedRouteList) Len() int {
	return len(r)
}

func (r tlsTerminatedRouteList) Less(i, j int) bool {
	return r[i].Path < r[j].Path
}

func (r tlsTerminatedRouteList) Swap(i, j int) {
	swap(r, i, j)
}

// tlsPassThroughRoute is need for the json translation from the TLSPassThroughRoute CR to the json voltron expects to
// see for a route.
type tlsPassThroughRoute struct {
	// Destination is the destination URL
	Destination string `json:"destination"`

	// ServerName
	ServerName string `json:"serverName"`
}

type tlsPassThroughRouteList []*tlsPassThroughRoute

func (r tlsPassThroughRouteList) Len() int {
	return len(r)
}

func (r tlsPassThroughRouteList) Less(i, j int) bool {
	return (r)[i].ServerName < (r)[j].ServerName
}

func (r tlsPassThroughRouteList) Swap(i, j int) {
	swap(r, i, j)
}

func swap[R any](list []R, i, j int) {
	tmp := list[i]
	list[i] = list[j]
	list[j] = tmp
}

// VoltronRouteConfigBuilder is an interface that provides methods to build a VoltronRouteConfig.
// Implementations of this interface should provide methods to add different types of routes,
// such as TLSTerminatedRoute and TLSPassThroughRoute, as well as methods to add ConfigMaps
// and Secrets to the route configuration to generate annotations that change when the contents of
// objects change (used to restart Voltron). The Build method should be used to create the final
// VoltronRouteConfig object.
type VoltronRouteConfigBuilder interface {
	// AddTLSTerminatedRoute adds TLSTerminatedRoutes to the config builder. When Build is called, the route is parsed
	// and validated and the route is added to the ConfigMap mounted to voltron to configure the tls terminated routes.
	//
	// If CAs or MTLS certs / keys are referenced in the spec the Config Maps and Secrets containing
	// those values must be added through AddConfigMap or AddSecret. This is so we can track when these values change.
	AddTLSTerminatedRoute(routes operatorv1.TLSTerminatedRoute)

	// AddTLSPassThroughRoute adds AddTLSPassThroughRoutes to the config builder. When Build is called, the route is parsed
	// and validated and the route is added to the ConfigMap mounted to voltron to configure the tls pass through routes.
	AddTLSPassThroughRoute(routes operatorv1.TLSPassThroughRoute)

	// AddConfigMap accepts a Config Map referenced by a TLS terminated route. This is used to detect changes to ConfigMaps
	// that will be mounted by the VoltronRouteConfig so Voltron can be restarted if the value changes.
	AddConfigMap(configMap *corev1.ConfigMap)

	// AddSecret accepts a Secret referenced by a TLS terminated route. This is used to detect changes to Secrets
	// that will be mounted by the VoltronRouteConfig so Voltron can be restarted if the value changes.
	AddSecret(secret *corev1.Secret)
	Build() (*VoltronRouteConfig, error)
}

type voltronRouteConfigBuilder struct {
	mountedConfigMaps map[string]struct{}
	mountedSecrets    map[string]struct{}

	volumeMounts []corev1.VolumeMount
	volumes      []corev1.Volume
	toAnnotate   map[string]string

	configMaps map[string]*corev1.ConfigMap
	secrets    map[string]*corev1.Secret

	tlsTerminatedRoutes  []operatorv1.TLSTerminatedRoute
	tlsPassThroughRoutes []operatorv1.TLSPassThroughRoute
}

func NewVoltronRouteConfigBuilder() VoltronRouteConfigBuilder {
	return &voltronRouteConfigBuilder{
		configMaps:        map[string]*corev1.ConfigMap{},
		secrets:           map[string]*corev1.Secret{},
		mountedConfigMaps: map[string]struct{}{},
		mountedSecrets:    map[string]struct{}{},
		toAnnotate:        map[string]string{},
	}
}

func (builder *voltronRouteConfigBuilder) AddConfigMap(configMap *corev1.ConfigMap) {
	if _, ok := builder.configMaps[configMap.Name]; !ok {
		builder.configMaps[configMap.Name] = configMap
	}
}

func (builder *voltronRouteConfigBuilder) AddSecret(secret *corev1.Secret) {
	if _, ok := builder.secrets[secret.Name]; !ok {
		builder.secrets[secret.Name] = secret
	}
}

func (builder *voltronRouteConfigBuilder) AddTLSTerminatedRoute(route operatorv1.TLSTerminatedRoute) {
	builder.tlsTerminatedRoutes = append(builder.tlsTerminatedRoutes, route)
}

func (builder *voltronRouteConfigBuilder) AddTLSPassThroughRoute(route operatorv1.TLSPassThroughRoute) {
	builder.tlsPassThroughRoutes = append(builder.tlsPassThroughRoutes, route)
}

func (builder *voltronRouteConfigBuilder) Build() (*VoltronRouteConfig, error) {
	var uiTLSTerminatedRoutes tlsTerminatedRouteList
	var tunnelTLSTerminatedRoutes tlsTerminatedRouteList
	var tunnelTLSPassThroughRoutes tlsPassThroughRouteList

	for _, route := range builder.tlsTerminatedRoutes {
		if route.Spec.CABundle == nil {
			return nil, fmt.Errorf("CABundle is required")
		}

		r := &tlsTerminatedRoute{
			Destination: route.Spec.Destination,
			Path:        route.Spec.PathMatch.Path,
			PathRegexp:  route.Spec.PathMatch.PathRegexp,
			PathReplace: route.Spec.PathMatch.PathReplace,
		}

		switch route.Spec.Target {
		case operatorv1.TargetTypeUI:
			uiTLSTerminatedRoutes = append(uiTLSTerminatedRoutes, r)
			if route.Spec.Unauthenticated != nil {
				r.Unauthenticated = *route.Spec.Unauthenticated
			}
		case operatorv1.TargetTypeUpstreamTunnel:
			tunnelTLSTerminatedRoutes = append(tunnelTLSTerminatedRoutes, r)
		default:
			return nil, fmt.Errorf("unknown Target value %s", route.Spec.Target)
		}

		if route.Spec.CABundle != nil {
			path, err := builder.mountConfigMapReference(route.Spec.CABundle.Name, route.Spec.CABundle.Key)
			if err != nil {
				return nil, err
			}

			r.CABundlePath = path
		}

		// Require that either both MTLSCert and MTLSKey are set or neither are.
		if (route.Spec.ForwardingMTLSCert != nil && route.Spec.ForwardingMTLSKey == nil) || (route.Spec.ForwardingMTLSKey != nil && route.Spec.ForwardingMTLSCert == nil) {
			return nil, fmt.Errorf("must set both MTLSCert and MTLSKey, or neither for TLS terminated route %s", route.Name)
		}

		if route.Spec.ForwardingMTLSCert != nil {
			path, err := builder.mountSecretReference(route.Spec.ForwardingMTLSCert.Name, route.Spec.ForwardingMTLSCert.Key)
			if err != nil {
				return nil, err
			}
			r.ClientCertPath = path

			// At this point, if MTLSCert is set then MTLSKey will be set otherwise this if statement wouldn't be executed
			// or an error would have already been returned.
			path, err = builder.mountSecretReference(route.Spec.ForwardingMTLSKey.Name, route.Spec.ForwardingMTLSKey.Key)
			if err != nil {
				return nil, err
			}
			r.ClientKeyPath = path
		}
	}

	for _, route := range builder.tlsPassThroughRoutes {
		r := &tlsPassThroughRoute{
			Destination: route.Spec.Destination,
			ServerName:  route.Spec.SNIMatch.ServerName,
		}
		tunnelTLSPassThroughRoutes = append(tunnelTLSPassThroughRoutes, r)
	}

	routesData := map[string]string{}

	if len(uiTLSTerminatedRoutes) > 0 {
		jsonBytes, err := marshalRouteList(uiTLSTerminatedRoutes)
		if err != nil {
			return nil, err
		}

		routesData[uiTLSTerminatedRoutesKey] = string(jsonBytes)
	}

	if len(tunnelTLSTerminatedRoutes) > 0 {
		jsonBytes, err := marshalRouteList(tunnelTLSTerminatedRoutes)
		if err != nil {
			return nil, err
		}

		routesData[upstreamTunnelTLSTerminatedRoutesKey] = string(jsonBytes)
	}

	if len(tunnelTLSPassThroughRoutes) > 0 {
		jsonBytes, err := marshalRouteList(tunnelTLSPassThroughRoutes)
		if err != nil {
			return nil, err
		}

		routesData[upstreamTunnelTLSPassThroughRoutesKey] = string(jsonBytes)
	}

	// Add the config map so mountConfigMap can add the annotation for the data.
	builder.AddConfigMap(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: voltronRoutesConfigMapName,
		},
		Data: routesData,
	})

	if _, err := builder.mountConfigMapReference(voltronRoutesConfigMapName, ""); err != nil {
		return nil, err
	}

	sort.Sort(ByVolumeMountName(builder.volumeMounts))
	sort.Sort(ByVolumeName(builder.volumes))

	return &VoltronRouteConfig{
		routesData:   routesData,
		volumeMounts: builder.volumeMounts,
		volumes:      builder.volumes,
		annotations:  builder.generateAnnotations(),
	}, nil
}

func marshalRouteList[R sort.Interface](list R) ([]byte, error) {
	sort.Sort(list)

	jsonBytes, err := json.MarshalIndent(list, "", "\t")
	if err != nil {
		return nil, err
	}

	return jsonBytes, nil
}

func (builder *voltronRouteConfigBuilder) mountConfigMapReference(name, key string) (string, error) {
	defaultMode := int32(420)

	configMap := builder.configMaps[name]
	if configMap == nil {
		return "", fmt.Errorf("the contents for ConfigMap '%s' weren't provided, and are needed to generate annotations", name)
	}

	if _, ok := builder.mountedConfigMaps[name]; !ok {
		// Prefix the volume name to avoid collisions with secrets that have the same name.
		volumeName := fmt.Sprintf("cm-%s", name)

		// Use a different folder for secrets and configmaps to avoid mounting collisions.
		mountLocation := fmt.Sprintf("%s/%s", configMapFolder, name)
		volumeMount := corev1.VolumeMount{Name: volumeName, MountPath: mountLocation, ReadOnly: true}

		volume := corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: name},
					DefaultMode:          &defaultMode,
				},
			},
		}

		builder.volumeMounts = append(builder.volumeMounts, volumeMount)
		builder.volumes = append(builder.volumes, volume)

		var keys []string
		for k := range configMap.Data {
			keys = append(keys, k)
		}

		sort.Strings(keys)
		for _, k := range keys {
			builder.addAnnotation(fmt.Sprintf("cm-%s-%s", configMap.Name, strings.ToLower(k)), configMap.Data[k])
		}

		builder.mountedConfigMaps[name] = struct{}{}
	}

	return fmt.Sprintf("%s/%s/%s", configMapFolder, name, key), nil
}

// Generate annotations takes the keys / values we need to add annotations for and ensures they're formatted correctly,
// i.e. are lower case and within the perceptible length. If the keys are too long, they are trimmed to 63 characters.
// If two trimmed keys result in a conflict, the last bytes of the conflicting key are replaced with an incremental number
// such that the length still remains 63 characters. This process continues, incrementing the prefix, until a non-conflicting
// key has been generated.
//
// The keys are sorted before we generate the annotations, ensuring that the conflict resolution logic is deterministic.
func (builder *voltronRouteConfigBuilder) generateAnnotations() map[string]string {
	const maxAnnotationLen = 63

	var keys []string
	for key := range builder.toAnnotate {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	annotations := map[string]string{}
	for _, key := range keys {
		formattedKey := fmt.Sprintf("%s-%s", routesAnnotationPrefix, strings.ToLower(key))
		if len(formattedKey) > maxAnnotationLen {
			formattedKey = formattedKey[0:maxAnnotationLen]
		}

		// Just in case there's a collision
		for i := 1; ; i++ {
			if _, ok := annotations[formattedKey]; !ok {
				break
			}
			suffix := strconv.Itoa(i)
			formattedKey = formattedKey[0:len(formattedKey)-len(suffix)] + suffix
		}

		annotations[formattedKey] = builder.toAnnotate[key]
	}

	return annotations
}

// addAnnotation adds the key and value to the annotation map. It ensures the key is lower case, and if it's length is
// greater than 55 characters it takes the first 55 characters and appends the first 6 characters of a hash of the key.
// This ensures that we're below the 63 character limit, but keys that have the same first 63 characters won't conflict
// with annotation keys.
func (builder *voltronRouteConfigBuilder) addAnnotation(key string, value string) {
	builder.toAnnotate[key] = rmeta.AnnotationHash(value)
}

func (builder *voltronRouteConfigBuilder) mountSecretReference(name, key string) (string, error) {
	defaultMode := int32(420)

	secret := builder.secrets[name]

	if secret == nil {
		return "", fmt.Errorf("the contents for Secret '%s' weren't provided, and are needed to generate annotations", name)
	}

	if _, ok := builder.mountedSecrets[name]; !ok {
		// Prefix the volume name to avoid collisions with secrets that have the same name.
		volumeName := fmt.Sprintf("scrt-%s", name)

		// Use a different folder for secrets and configmaps to avoid mounting collisions.
		mountLocation := fmt.Sprintf("%s/%s", secretsFolder, name)
		volumeMount := corev1.VolumeMount{Name: volumeName, MountPath: mountLocation, ReadOnly: true}

		volume := corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  name,
					DefaultMode: &defaultMode,
				},
			},
		}

		builder.volumeMounts = append(builder.volumeMounts, volumeMount)
		builder.volumes = append(builder.volumes, volume)

		var keys []string
		for k := range secret.Data {
			keys = append(keys, k)
		}

		sort.Strings(keys)
		for _, k := range keys {
			builder.addAnnotation(fmt.Sprintf("s-%s-%s", secret.Name, k), string(secret.Data[k]))
		}

		builder.mountedSecrets[name] = struct{}{}
	}

	return fmt.Sprintf("%s/%s/%s", secretsFolder, name, key), nil
}

// VoltronRouteConfig contains everything needed to configure the voltron pod / container with routes via a mounted file.
// It contains the volumes and volume mounts needed to mount the config map with the routes, as well as the CA, certs,
// keys.
//
// It provides functions for getting an annotation based of the mounted config maps / secrets to detect changes, as well
// as the env variables needed to configure the file paths to tell voltron where to look for the routes.
type VoltronRouteConfig struct {
	routesData   map[string]string
	volumeMounts []corev1.VolumeMount
	volumes      []corev1.Volume
	annotations  map[string]string
}

type ByVolumeMountName []corev1.VolumeMount

func (m ByVolumeMountName) Len() int           { return len(m) }
func (m ByVolumeMountName) Less(i, j int) bool { return m[i].Name < m[j].Name }
func (m ByVolumeMountName) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }

type ByVolumeName []corev1.Volume

func (m ByVolumeName) Len() int           { return len(m) }
func (m ByVolumeName) Less(i, j int) bool { return m[i].Name < m[j].Name }
func (m ByVolumeName) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }

// Volumes returns the volumes that Voltron needs to be configured with (references to ConfigMaps and Secrets in the
// TLSTerminatedRoute CRs).
func (cfg *VoltronRouteConfig) Volumes() []corev1.Volume {
	return cfg.volumes
}

// VolumeMounts returns the volume mounts that Voltron needs to be configured with (references to ConfigMaps and Secrets in the
// TLSTerminatedRoute CRs).
func (cfg *VoltronRouteConfig) VolumeMounts() []corev1.VolumeMount {
	return cfg.volumeMounts
}

// RoutesConfigMap returns the config map the contains the routes that voltron is to be configured with. This has been
// parsed from the TLSTerminatedRoute and the TLSPassThroughRoute CRs.
//
// The namespace parameter is used to assign the namespace that the ConfigMap should be created in.
func (cfg *VoltronRouteConfig) RoutesConfigMap(namespace string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      voltronRoutesConfigMapName,
			Namespace: namespace,
		},
		Data: cfg.routesData,
	}
}

// EnvVars returns a list of env vars that contain the paths to the route files that routes Config Map is mounted to.
func (cfg *VoltronRouteConfig) EnvVars() []corev1.EnvVar {
	var envVars []corev1.EnvVar
	if _, ok := cfg.routesData[uiTLSTerminatedRoutesKey]; ok {
		envVars = append(envVars, corev1.EnvVar{Name: "VOLTRON_UI_TLS_TERMINATED_ROUTES_PATH", Value: fmt.Sprintf("%s/%s", voltronRoutesFolderPath, uiTLSTerminatedRoutesKey)})
	}
	if _, ok := cfg.routesData[upstreamTunnelTLSTerminatedRoutesKey]; ok {
		envVars = append(envVars, corev1.EnvVar{Name: "VOLTRON_UPSTREAM_TUNNEL_TLS_TERMINATED_ROUTES_PATH", Value: fmt.Sprintf("%s/%s", voltronRoutesFolderPath, upstreamTunnelTLSTerminatedRoutesKey)})
	}
	if _, ok := cfg.routesData[upstreamTunnelTLSPassThroughRoutesKey]; ok {
		envVars = append(envVars, corev1.EnvVar{Name: "VOLTRON_UPSTREAM_TUNNEL_TLS_PASS_THROUGH_ROUTES_PATH", Value: fmt.Sprintf("%s/%s", voltronRoutesFolderPath, upstreamTunnelTLSPassThroughRoutesKey)})
	}

	return envVars
}

func (cfg *VoltronRouteConfig) Annotations() map[string]string {
	return cfg.annotations
}
