// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/tigera/operator/pkg/common/k8svalidation"
	rcc "github.com/tigera/operator/pkg/render/common/components"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateContainer is a function that validates the given container.
type ValidateContainer func(container corev1.Container) error

// NoContainersDefined is a container validation function that is used when no container is expected.
var NoContainersDefined ValidateContainer = func(container corev1.Container) error {
	return fmt.Errorf("container %q is invalid. No containers are expected", container.Name)
}

// ValidateReplicatedPodResourceOverrides validates the given replicated pod resource overrides.
// validateContainerFn and validateInitContainerFn are used to validate the container overrides.
func ValidateReplicatedPodResourceOverrides(overrides any, validateContainerFn ValidateContainer, validateInitContainerFn ValidateContainer) error {
	if md := rcc.GetMetadata(overrides); md != nil {
		if err := validateMetadata(md); err != nil {
			return fmt.Errorf("metadata is invalid: %w", err)
		}
	}
	if minReadySeconds := rcc.GetMinReadySeconds(overrides); minReadySeconds != nil {
		if *minReadySeconds < 0 {
			return fmt.Errorf("spec.MinReadySeconds must be greater than or equal to 0")
		}
	}
	if md := rcc.GetPodTemplateMetadata(overrides); md != nil {
		if err := validateMetadata(md); err != nil {
			return fmt.Errorf("spec.Template.Metadata is invalid: %w", err)
		}
	}
	if initContainers := rcc.GetInitContainers(overrides); len(initContainers) > 0 {
		for _, c := range initContainers {
			if err := validateInitContainerFn(c); err != nil {
				return fmt.Errorf("spec.Template.Spec.InitContainers[%q] is invalid: %w", c.Name, err)
			}
		}
	}
	if containers := rcc.GetContainers(overrides); len(containers) > 0 {
		for _, c := range containers {
			if err := validateContainerFn(c); err != nil {
				return fmt.Errorf("spec.Template.Spec.Containers[%q] is invalid: %w", c.Name, err)
			}
		}
	}
	if affinity := rcc.GetAffinity(overrides); affinity != nil {
		if errs := k8svalidation.ValidateAffinity(affinity, field.NewPath("spec", "template", "spec", "affinity")); errs.ToAggregate() != nil {
			return fmt.Errorf("spec.Template.Spec.Affinity is invalid: %w", errs.ToAggregate())
		}
	}
	if nodeSelector := rcc.GetNodeSelector(overrides); len(nodeSelector) > 0 {
		if err := k8svalidation.ValidatePodSpecNodeSelector(nodeSelector, field.NewPath("spec", "template", "spec", "nodeSelector")); err.ToAggregate() != nil {
			return fmt.Errorf("spec.Template.Spec.NodeSelector is invalid: %w", err.ToAggregate())
		}
	}
	if topologySpreadConstraints := rcc.GetTopologySpreadConstraints(overrides); len(topologySpreadConstraints) > 0 {
		if err := k8svalidation.ValidateTopologySpreadConstraints(topologySpreadConstraints, field.NewPath("spec", "template", "spec", "topologySpreadConstraints")); err.ToAggregate() != nil {
			return fmt.Errorf("spec.Template.Spec.TopologySpreadConstraints is invalid: %w", err.ToAggregate())
		}
	}

	if tolerations := rcc.GetTolerations(overrides); len(tolerations) > 0 {
		if errs := k8svalidation.ValidateTolerations(tolerations, field.NewPath("spec", "template", "spec", "tolerations")); errs.ToAggregate() != nil {
			return fmt.Errorf("spec.Template.Spec.Tolerations is invalid: %w", errs.ToAggregate())
		}
	}

	tgp := rcc.GetTerminationGracePeriodSeconds(overrides)
	if tgp != nil && *tgp < 0 {
		return fmt.Errorf("spec.Template.Spec.TerminationGracePeriodSeconds is invalid: cannot be negative")
	}

	if st := rcc.GetDeploymentStrategy(overrides); st != nil {
		if err := k8svalidation.ValidateDeploymentStrategy(st, field.NewPath("spec", "strategy")); err.ToAggregate() != nil {
			return fmt.Errorf("spec.Strategy is invalid: %w", err.ToAggregate())
		}
	}

	return nil
}

// validateMetadata validates the given Metadata.
func validateMetadata(metadata *operatorv1.Metadata) error {
	if metadata == nil {
		return nil
	}
	errs := field.ErrorList{}
	errs = append(errs, k8svalidation.ValidateLabels(metadata.Labels, field.NewPath("metadata", "labels"))...)
	errs = append(errs, k8svalidation.ValidateAnnotations(metadata.Annotations, field.NewPath("metadata", "annotations"))...)
	return errs.ToAggregate()
}
