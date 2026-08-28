// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Package extensionstest holds shared helpers for exercising an extension's Modify
// dispatch against raw object lists.
package extensionstest

import (
	client "sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/render"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/kubecontrollers"
	"github.com/projectcalico/calico/operator/pkg/render/webhooks"
)

// StubComponent adapts raw object lists to a render.Component. The typed stubs embed
// it to satisfy what an extension dispatches on.
type StubComponent struct {
	Create, Delete []client.Object
}

func (s StubComponent) ResolveImages(*operatorv1.ImageSet) error {
	return nil
}

func (s StubComponent) Objects() ([]client.Object, []client.Object) {
	return s.Create, s.Delete
}

func (s StubComponent) Ready() bool {
	return true
}

func (s StubComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

type NodeStub struct {
	StubComponent

	Cfg *render.NodeConfiguration
}

func (s NodeStub) NodeConfig() *render.NodeConfiguration {
	return s.Cfg
}

type TyphaStub struct {
	StubComponent

	Cfg *render.TyphaConfiguration
}

func (s TyphaStub) TyphaConfig() *render.TyphaConfiguration {
	return s.Cfg
}

type WindowsStub struct {
	StubComponent

	Cfg *render.WindowsConfiguration
}

func (s WindowsStub) WindowsConfig() *render.WindowsConfiguration {
	return s.Cfg
}

type GuardianStub struct {
	StubComponent

	Cfg *render.GuardianConfiguration
}

func (s GuardianStub) GuardianConfig() *render.GuardianConfiguration {
	return s.Cfg
}

type GuardianPolicyStub struct {
	StubComponent

	Cfg *render.GuardianConfiguration
}

func (s GuardianPolicyStub) GuardianPolicyConfig() *render.GuardianConfiguration {
	return s.Cfg
}

type APIServerStub struct {
	StubComponent

	Cfg *render.APIServerConfiguration
}

func (s APIServerStub) APIServerConfig() *render.APIServerConfiguration {
	return s.Cfg
}

type APIServerPolicyStub struct {
	StubComponent

	Cfg *render.APIServerConfiguration
}

func (s APIServerPolicyStub) APIServerPolicyConfig() *render.APIServerConfiguration {
	return s.Cfg
}

type KubeControllersStub struct {
	StubComponent

	Cfg *kubecontrollers.KubeControllersConfiguration
}

func (s KubeControllersStub) KubeControllersConfig() *kubecontrollers.KubeControllersConfiguration {
	return s.Cfg
}

type KubeControllersPolicyStub struct {
	StubComponent

	Cfg *kubecontrollers.KubeControllersConfiguration
}

func (s KubeControllersPolicyStub) KubeControllersPolicyConfig() *kubecontrollers.KubeControllersConfiguration {
	return s.Cfg
}

type WebhooksStub struct {
	StubComponent

	Cfg *webhooks.Configuration
}

func (s WebhooksStub) WebhooksConfig() *webhooks.Configuration {
	return s.Cfg
}
