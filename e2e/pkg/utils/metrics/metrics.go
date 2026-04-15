// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package metrics

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

// EnsurePrometheusMetricsEnabled enables PrometheusMetricsEnabled in the
// default FelixConfiguration. The returned cleanup func, if not-nil, restores
// the original value (ideally via DeferCleanup).
func EnsurePrometheusMetricsEnabled(cli client.Client) (cleanup func(), err error) {
	framework.Logf("Ensuring Prometheus metrics are enabled in FelixConfiguration")

	cleanup, err = utils.ConfigureWithCleanup(cli, client.ObjectKey{Name: "default"}, &v3.FelixConfiguration{}, func(cfg *v3.FelixConfiguration) {
		cfg.Spec.PrometheusMetricsEnabled = ptr.To(true)
	})

	if err != nil {
		return cleanup, fmt.Errorf("Couldn't enable Prometheus metrics: %w", err)
	}

	return cleanup, nil
}

type MetricScraper struct {
	pod           *v1.Pod
	metricsEPIP   string
	metricsEPPort int
}

// NewMetricScraper creates a long-lived Alpine pod (via conncheck.CreateClientPod)
// that scrapes Prometheus metrics from a given metrics endpoint (IP:port). Returns the
// scraper and a cleanup function that deletes the pod.
func NewMetricScraper(f *framework.Framework, nodeIP string, metricsPort int) (scr *MetricScraper, cleanup func() error, err error) {
	scr = &MetricScraper{
		metricsEPIP:   nodeIP,
		metricsEPPort: metricsPort,
	}

	safeIP := strings.NewReplacer(":", "-", ".", "-", "[", "", "]", "").Replace(nodeIP)
	pod, err := conncheck.CreateClientPod(f, f.Namespace, fmt.Sprintf("metrics-scraper-%s-%d", safeIP, metricsPort), nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create metrics scraper pod: %w", err)
	}

	timeout := 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err = e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, pod.Name, pod.Namespace, timeout)
	if err != nil {
		delCtx, delCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer delCancel()
		_ = f.ClientSet.CoreV1().Pods(pod.Namespace).Delete(delCtx, pod.Name, metav1.DeleteOptions{})
		return nil, nil, fmt.Errorf("timed out waiting for metrics scraper pod to become Running: %w", err)
	}

	// Re-read the pod to get its assigned IP and node.
	getCtx, getCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer getCancel()
	pod, err = f.ClientSet.CoreV1().Pods(pod.Namespace).Get(getCtx, pod.Name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get metrics scraper pod after it became Running: %w", err)
	}

	framework.Logf("Created metrics scraper pod %s", pod.Name)
	scr.pod = pod
	return scr, func() error {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		err := f.ClientSet.CoreV1().Pods(pod.Namespace).Delete(
			cleanupCtx, pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to delete metrics scraper pod: %w", err)
		}
		return nil
	}, nil
}

// Metric returns a func which can be repeatedly-called to poll a metric
// on the given endpoint.
func (scraper MetricScraper) Metric(metricName string) func() (float64, error) {
	return func() (float64, error) {
		errOutFile := fmt.Sprintf("metrics-err-%s-%d", metricName, time.Now().UnixNano())
		url := "http://" + net.JoinHostPort(scraper.metricsEPIP, strconv.Itoa(scraper.metricsEPPort)) + "/metrics"
		output, err := conncheck.ExecInPod(scraper.pod, "sh", "-c",
			fmt.Sprintf("wget -qO- %s 2>/tmp/%s", url, errOutFile))
		if err != nil {
			catCmd := fmt.Sprintf("cat /tmp/%s", errOutFile)
			errmsg, _ := conncheck.ExecInPod(scraper.pod, "sh", "-c", catCmd)
			return 0, fmt.Errorf("failed to scrape metrics at %s: %w: %s", url, err, errmsg)
		}

		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, metricName+" ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					return strconv.ParseFloat(parts[1], 64)
				}
			}
		}

		return 0, fmt.Errorf("metric %s not found in response from %s", metricName, url)
	}
}
