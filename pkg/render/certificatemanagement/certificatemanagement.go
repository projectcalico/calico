// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.

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

package certificatemanagement

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateManagement renders your KeyPairs and TrustedBundle, thereby simplifying other render components.
func CertificateManagement(
	cfg *Config,
) render.Component {
	if cfg.TruthNamespace == "" {
		// Default to the "tigera-operator" namespace, that has
		// been traditionally used as the source-of-truth for secrets.
		cfg.TruthNamespace = common.OperatorNamespace()
	}
	return &component{
		cfg: cfg,
	}
}

// Config contains all the config CertificateManagement needs to render objects.
type Config struct {
	// The service accounts that are mounting the key pairs and may issue CSRs if installation.CertificateManagement is used.
	ServiceAccounts []string
	KeyPairOptions  []KeyPairOption
	Namespace       string
	TruthNamespace  string
	TrustedBundle   certificatemanagement.TrustedBundle
}

func NewKeyPairOption(keyPair certificatemanagement.KeyPairInterface, renderInTruthNS, renderInAppNS bool) KeyPairOption {
	return KeyPairOption{
		keyPair:                keyPair,
		renderInTruthNamespace: renderInTruthNS,
		renderInAppNamespace:   renderInAppNS,
	}
}

type KeyPairOption struct {
	keyPair certificatemanagement.KeyPairInterface

	// Whether or not we should install this in the "source of truth" namespace.
	renderInTruthNamespace bool

	// Whether or not we should install this into the application namespace.
	renderInAppNamespace bool
}

type component struct {
	cfg *Config
}

func (c component) ResolveImages(*operatorv1.ImageSet) error {
	return nil
}

func (c component) Objects() (objsToCreate, objsToDelete []client.Object) {
	if c.cfg.TrustedBundle != nil {
		// Create the trusted bundle in the namespace that we're installing into.
		objsToCreate = append(objsToCreate, c.cfg.TrustedBundle.ConfigMap(c.cfg.Namespace))
	}

	// Iterate each KeyPair and create it where needed. A KeyPair may need to be installed one or more of:
	// - The "source of truth" namespace, commonly tigera-operator.
	// - The target namespace that we're installing into.
	var needsCSRRoleAndBinding bool
	for _, keyPairCreator := range c.cfg.KeyPairOptions {
		keyPair := keyPairCreator.keyPair
		if keyPair == nil {
			continue
		}

		if keyPair.UseCertificateManagement() {
			if keyPairCreator.renderInTruthNamespace {
				objsToDelete = append(objsToDelete, keyPair.Secret(c.cfg.TruthNamespace))
			}
			if keyPairCreator.renderInAppNamespace {
				objsToDelete = append(objsToDelete, keyPair.Secret(c.cfg.Namespace))
			}
			needsCSRRoleAndBinding = true
		} else {
			if keyPairCreator.renderInTruthNamespace && (!keyPair.BYO() || keyPair.GetName() == certificatemanagement.CASecretName || keyPair.GetName() == certificatemanagement.TenantCASecretName) {
				objsToCreate = append(objsToCreate, keyPair.Secret(c.cfg.TruthNamespace))
			}
			if keyPairCreator.renderInAppNamespace {
				objsToCreate = append(objsToCreate, keyPair.Secret(c.cfg.Namespace))
			}
		}
	}

	if needsCSRRoleAndBinding {
		for _, sa := range c.cfg.ServiceAccounts {
			objsToCreate = append(objsToCreate, certificatemanagement.CSRClusterRoleBinding(sa, c.cfg.Namespace))
		}
	} else {
		for _, sa := range c.cfg.ServiceAccounts {
			objsToDelete = append(objsToDelete, certificatemanagement.CSRClusterRoleBinding(sa, c.cfg.Namespace))
		}
	}
	return
}

func (c component) Ready() bool {
	return true
}

func (c component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}
