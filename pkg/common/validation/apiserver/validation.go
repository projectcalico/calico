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

package validation

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/tigera/operator/pkg/common/k8svalidation"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateAPIServerDeploymentContainer validates the given container is a valid API server Deployment container.
func ValidateAPIServerDeploymentContainer(container corev1.Container) error {
	errs := k8svalidation.ValidateResourceRequirements(&container.Resources, field.NewPath("spec", "template", "spec", "containers"))
	errs = append(errs, validateContainerPorts(container)...)
	return errs.ToAggregate()
}

// ValidateAPIServerDeploymentInitContainer validates the given container is a valid API server Deployment init container.
func ValidateAPIServerDeploymentInitContainer(container corev1.Container) error {
	errs := k8svalidation.ValidateResourceRequirements(&container.Resources, field.NewPath("spec", "template", "spec", "initContainers"))
	return errs.ToAggregate()
}

// validateContainerPorts validates the given container's ports comparing the port name against the container name.
func validateContainerPorts(container corev1.Container) field.ErrorList {
	allErrs := field.ErrorList{}
	fldPath := field.NewPath("spec", "template", "spec", "containers", "ports", "name")
	ports := container.Ports
	// Validate if the port name can be attributed to the container.
	for _, port := range ports {
		if (port.Name == render.APIServerPortName && container.Name != render.APIServerContainerName) ||
			(port.Name == render.QueryServerPortName && container.Name != render.TigeraAPIServerQueryServerContainerName) ||
			(port.Name == render.L7AdmissionControllerPortName && container.Name != render.L7AdmissionControllerContainerName) {
			msg := fmt.Sprintf("port name %s is not valid for container %s", port.Name, container.Name)
			allErrs = append(allErrs, field.Invalid(fldPath, port.Name, msg))
		}
	}

	return allErrs
}
