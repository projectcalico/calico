// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package monitor

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render/monitor"
)

func addAlertmanagerWatch(c ctrlruntime.Controller) error {
	return utils.AddNamespacedWatch(c, &monitoringv1.Alertmanager{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.AlertmanagersKind, APIVersion: monitor.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: monitor.CalicoNodeAlertmanager, Namespace: common.TigeraPrometheusNamespace},
	}, &handler.EnqueueRequestForObject{})
}

func addPrometheusWatch(c ctrlruntime.Controller) error {
	return utils.AddNamespacedWatch(c, &monitoringv1.Prometheus{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.PrometheusesKind, APIVersion: monitor.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: monitor.CalicoNodePrometheus, Namespace: common.TigeraPrometheusNamespace},
	}, &handler.EnqueueRequestForObject{})
}

func addPrometheusRuleWatch(c ctrlruntime.Controller) error {
	return utils.AddNamespacedWatch(c, &monitoringv1.PrometheusRule{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.PrometheusRuleKind, APIVersion: monitor.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: monitor.TigeraPrometheusRule, Namespace: common.TigeraPrometheusNamespace},
	}, &handler.EnqueueRequestForObject{})
}

func addServiceMonitorCalicoNodeWatch(c ctrlruntime.Controller) error {
	return utils.AddNamespacedWatch(c, &monitoringv1.ServiceMonitor{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: monitor.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: monitor.CalicoNodeMonitor, Namespace: common.TigeraPrometheusNamespace},
	}, &handler.EnqueueRequestForObject{})
}

func addServiceMonitorElasticsearchWatch(c ctrlruntime.Controller) error {
	return utils.AddNamespacedWatch(c, &monitoringv1.ServiceMonitor{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: monitor.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: monitor.ElasticsearchMetrics, Namespace: common.TigeraPrometheusNamespace},
	}, &handler.EnqueueRequestForObject{})
}

func addServiceMonitorFluentBitWatch(c ctrlruntime.Controller) error {
	return utils.AddNamespacedWatch(c, &monitoringv1.ServiceMonitor{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: monitor.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: monitor.FluentBitMetrics, Namespace: common.TigeraPrometheusNamespace},
	}, &handler.EnqueueRequestForObject{})
}

func addServiceMonitorKubeControllerWatch(c ctrlruntime.Controller) error {
	return utils.AddNamespacedWatch(c, &monitoringv1.ServiceMonitor{
		TypeMeta:   metav1.TypeMeta{Kind: monitoringv1.ServiceMonitorsKind, APIVersion: monitor.MonitoringAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: monitor.KubeControllerMetrics, Namespace: common.TigeraPrometheusNamespace},
	}, &handler.EnqueueRequestForObject{})
}

func addWatch(c ctrlruntime.Controller) error {
	var err error
	if err = addAlertmanagerWatch(c); err != nil {
		return fmt.Errorf("failed to watch Alertmanager resource: %w", err)
	}

	if err = addPrometheusWatch(c); err != nil {
		return fmt.Errorf("failed to watch Prometheus resource: %w", err)
	}

	if err = addPrometheusRuleWatch(c); err != nil {
		return fmt.Errorf("failed to watch PrometheusRule resource: %w", err)
	}

	if err = addServiceMonitorCalicoNodeWatch(c); err != nil {
		return fmt.Errorf("failed to watch ServiceMonitor calico-node-monitor resource: %w", err)
	}

	if err = addServiceMonitorElasticsearchWatch(c); err != nil {
		return fmt.Errorf("failed to watch ServiceMonitor elasticsearch-metrics resource: %w", err)
	}

	if err = addServiceMonitorFluentBitWatch(c); err != nil {
		return fmt.Errorf("failed to watch ServiceMonitor %s resource: %w", monitor.FluentBitMetrics, err)
	}

	if err = addServiceMonitorKubeControllerWatch(c); err != nil {
		return fmt.Errorf("failed to watch ServiceMonitor calico-kube-controller-metrics resource: %w", err)
	}

	if err = utils.AddSecretsWatch(c, monitor.AlertmanagerConfigSecret, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("failed to watch Alertmanager configuration secret in Operator namespace: %w", err)
	}

	if err = utils.AddSecretsWatch(c, monitor.AlertmanagerConfigSecret, common.TigeraPrometheusNamespace); err != nil {
		return fmt.Errorf("failed to watch Alertmanager configuration secret in Prometheus namespace: %w", err)
	}

	return err
}

func requiresPrometheusResources(client kubernetes.Interface) error {
	resources, err := client.Discovery().ServerResourcesForGroupVersion("monitoring.coreos.com/v1")
	if err != nil {
		return err
	}

	expectedResources := map[string]bool{
		monitoringv1.AlertmanagersKind:   false,
		monitoringv1.PodMonitorsKind:     false,
		monitoringv1.PrometheusesKind:    false,
		monitoringv1.ServiceMonitorsKind: false,
	}

	for _, r := range resources.APIResources {
		switch r.Kind {
		case monitoringv1.AlertmanagersKind,
			monitoringv1.PodMonitorsKind,
			monitoringv1.PrometheusesKind,
			monitoringv1.ServiceMonitorsKind:
			expectedResources[r.Kind] = true
		}
	}

	for k, v := range expectedResources {
		if !v {
			return fmt.Errorf("failed to find Prometheus resource: %s", k)
		}
	}

	return nil
}

func waitToAddPrometheusWatch(c ctrlruntime.Controller, client kubernetes.Interface, log logr.Logger, readyFlag *utils.ReadyFlag) {
	const (
		initBackoff = 30 * time.Second
		maxBackoff  = 8 * time.Minute
	)

	duration := initBackoff
	ticker := time.NewTicker(duration)
	defer ticker.Stop()
	for range ticker.C {
		duration = duration * 2
		if duration >= maxBackoff {
			duration = maxBackoff
		}
		ticker.Reset(duration)

		if err := requiresPrometheusResources(client); err != nil {
			log.Info(fmt.Sprintf("%v. monitor-controller will retry.", err))
		} else {
			// watch for prometheus resource changes
			if err := addWatch(c); err != nil {
				log.Info(fmt.Sprintf("%v. monitor-controller will retry.", err))
			} else {
				readyFlag.MarkAsReady()
				return
			}
		}
	}
}
