// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ImageSetSpec defines the desired state of ImageSet.
type ImageSetSpec struct {
	// Images is the list of images to use digests. All images that the operator will deploy
	// must be specified.
	Images []Image `json:"images,omitempty"`
}

type Image struct {
	// Image is an image that the operator deploys and instead of using the built in tag
	// the operator will use the Digest for the image identifier.
	// The value should be the *original* image name without registry or tag or digest.
	// For the image `docker.io/calico/node:v3.17.1` it should be represented as `calico/node`
	// The "Installation" spec allows defining custom image registries, paths or prefixes.
	// Even for custom images such as example.com/custompath/customprefix-calico-node:v3.17.1,
	// this value should still be `calico/node`.
	Image string `json:"image"`

	// Digest is the image identifier that will be used for the Image.
	// The field should not include a leading `@` and must be prefixed with `sha256:`.
	Digest string `json:"digest"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ImageSet is used to specify image digests for the images that the operator deploys.
// The name of the ImageSet is expected to be in the format `<variant>-<release>`.
// The `variant` used is `enterprise` if the InstallationSpec Variant is
// `CalicoEnterprise` or `TigeraSecureEnterprise`, otherwise it is `calico`.
// The `release` must match the version of the variant that the operator is built to deploy,
// this version can be obtained by passing the `--version` flag to the operator binary.
type ImageSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ImageSetSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ImageSetList contains a list of ImageSet
type ImageSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageSet{}, &ImageSetList{})
}
