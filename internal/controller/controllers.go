// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

package controller

import (
	"fmt"

	"github.com/tigera/operator/pkg/controller/options"
	ctrl "sigs.k8s.io/controller-runtime"
)

func AddToManager(mgr ctrl.Manager, options options.ControllerOptions) error {
	if err := (&IPPoolReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("IPPool"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "IPPool", err)
	}
	if err := (&InstallationReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Installation"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Installation", err)
	}
	if err := (&APIServerReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("APIServer"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "APIServer", err)
	}
	if err := (&IstioReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Istio"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller Istio: %v", err)
	}
	if err := (&ManagementClusterConnectionReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("ManagementClusterConnection"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "ManagementClusterConnection", err)
	}
	if err := (&TiersReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Tiers"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Tiers", err)
	}
	if err := (&SecretsReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Secrets"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Secrets", err)
	}
	if err := (&WindowsReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Windows"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller Windows: %v", err)
	}
	if err := (&CSRReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("CertificateSigningRequest"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "CSR", err)
	}
	if err := (&GatewayAPIReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "GatewayAPI", err)
	}
	if err := (&WhiskerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Whisker", err)
	}
	if err := (&GoldmaneReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Goldmane", err)
	}
	if err := (&KubeProxyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "KubeProxy", err)
	}
	if err := (&PodIPRecoveryReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("PodIPRecovery"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "PodIPRecovery", err)
	}
	// +kubebuilder:scaffold:builder

	// The controllers only the running variant supplies, added last so that a variant
	// can watch resources the core controllers own.
	return options.AddControllers(mgr)
}
