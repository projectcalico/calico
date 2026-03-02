// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package clientv3

import (
	"context"
	"errors"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// KubeControllersConfigurationInterface has methods to work with KubeControllersConfiguration resources.
type KubeControllersConfigurationInterface interface {
	Create(ctx context.Context, res *apiv3.KubeControllersConfiguration, opts options.SetOptions) (*apiv3.KubeControllersConfiguration, error)
	Update(ctx context.Context, res *apiv3.KubeControllersConfiguration, opts options.SetOptions) (*apiv3.KubeControllersConfiguration, error)
	UpdateStatus(ctx context.Context, res *apiv3.KubeControllersConfiguration, opts options.SetOptions) (*apiv3.KubeControllersConfiguration, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.KubeControllersConfiguration, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.KubeControllersConfiguration, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.KubeControllersConfigurationList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// KubeControllersConfiguration implements KubeControllersConfigurationInterface
type kubeControllersConfiguration struct {
	client client
}

func (r kubeControllersConfiguration) validateAndFillDefaults(res *apiv3.KubeControllersConfiguration) error {
	if res.Spec.PrometheusMetricsPort == nil {
		var defaultPort = 9094
		res.Spec.PrometheusMetricsPort = &defaultPort
	}

	if res.Spec.Controllers.Node != nil {
		if res.Spec.Controllers.Node.LeakGracePeriod == nil {
			res.Spec.Controllers.Node.LeakGracePeriod = &metav1.Duration{Duration: 15 * time.Minute}
		}
	}

	if res.Spec.Controllers.LoadBalancer != nil {
		if res.Spec.Controllers.LoadBalancer.AssignIPs == "" {
			res.Spec.Controllers.LoadBalancer.AssignIPs = apiv3.AllServices
		}
	}

	// Validate and default HostEndpoint Template
	if res.Spec.Controllers.Node != nil && res.Spec.Controllers.Node.HostEndpoint != nil {
		if res.Spec.Controllers.Node.HostEndpoint.Templates != nil {
			templateName := make(map[string]bool)
			for _, template := range res.Spec.Controllers.Node.HostEndpoint.Templates {

				// Name can't be empty
				if template.GenerateName == "" {
					return cerrors.ErrorValidation{
						ErroredFields: []cerrors.ErroredField{{
							Name:   "KubeControllersConfiguration.Node.HostEndpoint.Templates",
							Reason: "Template name must be specified",
						}},
					}
				}

				if len(template.GenerateName) > validation.DNS1123SubdomainMaxLength {
					return cerrors.ErrorValidation{
						ErroredFields: []cerrors.ErroredField{{
							Name:   "KubeControllersConfiguration.Node.HostEndpoint.Templates",
							Reason: "Template name must be shorter than 253 characters",
						}},
					}
				}

				// Name must be unique as it's being used to ensure generated HostEndpoint name is unique
				if _, ok := templateName[template.GenerateName]; ok {
					return cerrors.ErrorValidation{
						ErroredFields: []cerrors.ErroredField{{
							Name:   "KubeControllersConfiguration.Node.HostEndpoint.Templates." + template.GenerateName,
							Reason: "Template name must be unique",
						}},
					}
				}
				templateName[template.GenerateName] = true

				// At least InterfaceCIDRs or InterfacePattern has to be set
				if len(template.InterfaceCIDRs) == 0 && template.InterfacePattern == "" {
					return cerrors.ErrorValidation{
						ErroredFields: []cerrors.ErroredField{{
							Name:   "KubeControllersConfiguration.Node.HostEndpoint.Templates." + template.GenerateName,
							Reason: "InterfaceCIDRs or InterfacePattern must be specified",
						}},
					}
				}

				// If a nodeSelector is not specified, then this template selects all nodes.
				if template.NodeSelector == "" {
					template.NodeSelector = "all()"
				}
			}
		}
	}

	return nil
}

// Create takes the representation of a KubeControllersConfiguration and creates it.
// Returns the stored representation of the KubeControllersConfiguration, and an error
// if there is any.
func (r kubeControllersConfiguration) Create(ctx context.Context, res *apiv3.KubeControllersConfiguration, opts options.SetOptions) (*apiv3.KubeControllersConfiguration, error) {
	err := r.validateAndFillDefaults(res)
	if err != nil {
		return nil, err
	}
	if err = validator.Validate(res); err != nil {
		return nil, err
	}

	if res.ObjectMeta.GetName() != "default" {
		return nil, errors.New("Cannot create a Kube Controllers Configuration resource with a name other than \"default\"")
	}
	out, err := r.client.resources.Create(ctx, opts, apiv3.KindKubeControllersConfiguration, res)
	if out != nil {
		return out.(*apiv3.KubeControllersConfiguration), err
	}
	return nil, err
}

// Update takes the representation of a KubeControllersConfiguration and updates it.
// Returns the stored representation of the KubeControllersConfiguration, and an error
// if there is any.
func (r kubeControllersConfiguration) Update(ctx context.Context, res *apiv3.KubeControllersConfiguration, opts options.SetOptions) (*apiv3.KubeControllersConfiguration, error) {
	err := r.validateAndFillDefaults(res)
	if err != nil {
		return nil, err
	}
	if err = validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, apiv3.KindKubeControllersConfiguration, res)
	if out != nil {
		return out.(*apiv3.KubeControllersConfiguration), err
	}
	return nil, err
}

// UpdateStatus takes the representation of a KubeControllersConfiguration and updates its status.
// Returns the stored representation of the KubeControllersConfiguration, and an error
// if there is any.
func (r kubeControllersConfiguration) UpdateStatus(ctx context.Context, res *apiv3.KubeControllersConfiguration, opts options.SetOptions) (*apiv3.KubeControllersConfiguration, error) {
	out, err := r.client.resources.UpdateStatus(ctx, opts, apiv3.KindKubeControllersConfiguration, res)
	if out != nil {
		return out.(*apiv3.KubeControllersConfiguration), err
	}
	return nil, err
}

// Delete takes name of the KubeControllersConfiguration and deletes it. Returns an
// error if one occurs.
func (r kubeControllersConfiguration) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.KubeControllersConfiguration, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv3.KindKubeControllersConfiguration, noNamespace, name)
	if out != nil {
		return out.(*apiv3.KubeControllersConfiguration), err
	}
	return nil, err
}

// Get takes name of the KubeControllersConfiguration, and returns the corresponding
// KubeControllersConfiguration object, and an error if there is any.
func (r kubeControllersConfiguration) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.KubeControllersConfiguration, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv3.KindKubeControllersConfiguration, noNamespace, name)
	if out != nil {
		return out.(*apiv3.KubeControllersConfiguration), err
	}
	return nil, err
}

// List returns the list of KubeControllersConfiguration objects that match the supplied options.
func (r kubeControllersConfiguration) List(ctx context.Context, opts options.ListOptions) (*apiv3.KubeControllersConfigurationList, error) {
	res := &apiv3.KubeControllersConfigurationList{}
	if err := r.client.resources.List(ctx, opts, apiv3.KindKubeControllersConfiguration, apiv3.KindKubeControllersConfigurationList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the KubeControllersConfiguration that
// match the supplied options.
func (r kubeControllersConfiguration) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv3.KindKubeControllersConfiguration, nil)
}
