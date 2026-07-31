// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

//go:build linux

package wireguard

import (
	"fmt"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/netlinkshim"
)

const (
	labelHostname      = "hostname"
	labelPublicKey     = "public_key"
	labelInterfaceName = "iface"
	labelListenPort    = "listen_port"
	labelPeerKey       = "peer_key"
	labelPeerEndpoint  = "peer_endpoint"
)

var _ prometheus.Collector = (*Metrics)(nil)

const (
	wireguardMetaFQName   = "wireguard_meta"
	wireguardMetaHelpText = "wireguard interface and runtime metadata"

	wireguardLatestHandshakeIntervalFQName   = "wireguard_latest_handshake_seconds"
	wireguardLatestHandshakeIntervalHelpText = "wireguard interface latest handshake unix timestamp in seconds to a peer"

	wireguardBytesSentFQName   = "wireguard_bytes_sent"
	wireguardBytesSentHelpText = "wireguard interface outgoing bytes count to peer"

	wireguardBytesRcvdFQName   = "wireguard_bytes_rcvd"
	wireguardBytesRcvdHelpText = "wireguard interface incoming bytes count from peer"

	defaultCollectionRatelimit = time.Second
)

type Metrics struct {
	hostname           string
	newWireguardClient func() (netlinkshim.Wireguard, error)
	wireguardClient    netlinkshim.Wireguard
	logCtx             *logrus.Entry

	rateLimitInterval time.Duration

	lock               sync.Mutex
	lastCollectionTime time.Time
	cachedMetrics      []prometheus.Metric
}

func (collector *Metrics) Describe(d chan<- *prometheus.Desc) {
	// Send nothing, this marks our collector as "unchecked", which we need
	// because our Collect() method is dynamic.
}

func (collector *Metrics) Collect(m chan<- prometheus.Metric) {
	metrics := collector.maybeRefresh()
	for _, met := range metrics {
		m <- met
	}
}

func (collector *Metrics) maybeRefresh() []prometheus.Metric {
	// Compute staleness relative to the time we were asked for the metrics
	// so that multiple concurrent calls will collect metrics only once even
	// if the collection was slow for some reason.
	collectCallTime := time.Now()

	collector.lock.Lock()
	defer collector.lock.Unlock()
	var metrics []prometheus.Metric
	if ct := collectCallTime.Sub(collector.lastCollectionTime); ct < collector.rateLimitInterval {
		collector.logCtx.WithFields(logrus.Fields{
			"since":              ct.String(),
			"ratelimit_interval": collector.rateLimitInterval.String(),
		}).Debug("refreshStats disallowed due to rate limit")
		metrics = collector.cachedMetrics
	} else {
		metrics = make([]prometheus.Metric, 0, len(collector.cachedMetrics))
		devices := collector.getDevices()
		collector.logCtx.WithFields(logrus.Fields{
			"count": len(devices),
			"dev":   devices,
		}).Debug("collect device metrics enumerated devices")
		metrics = collector.appendDeviceMetrics(devices, metrics)
		metrics = collector.appendDevicePeerMetrics(devices, metrics)
		collector.lastCollectionTime = time.Now()
		collector.cachedMetrics = metrics
	}

	return metrics
}

func MustNewWireguardMetrics() *Metrics {
	wg, err := NewWireguardMetrics()
	if err != nil {
		logrus.Panic(err)
	}
	return wg
}

func NewWireguardMetrics() (*Metrics, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	return NewWireguardMetricsWithShims(hostname, netlinkshim.NewRealWireguard, defaultCollectionRatelimit), nil
}

func NewWireguardMetricsWithShims(hostname string, newWireguardClient func() (netlinkshim.Wireguard, error), rateLimitInterval time.Duration) *Metrics {
	logrus.WithField("hostname", hostname).Debug("created wireguard collector for host")
	return &Metrics{
		hostname:           hostname,
		newWireguardClient: newWireguardClient,
		logCtx: logrus.WithFields(logrus.Fields{
			"prometheus_collector": "wireguard",
		}),

		rateLimitInterval: rateLimitInterval,
	}
}

func (collector *Metrics) getWireguardClient() (netlinkshim.Wireguard, error) {
	// lazily create wireguard client and cache it for future use
	if collector.wireguardClient == nil {
		wgClient, err := collector.newWireguardClient()
		if err != nil {
			return nil, err
		}
		collector.wireguardClient = wgClient
	}
	return collector.wireguardClient, nil
}

func (collector *Metrics) getDevices() []*wgtypes.Device {
	wgClient, err := collector.getWireguardClient()
	if err != nil {
		collector.logCtx.WithError(err).Debug("something went wrong initializing wireguard rpc client")
		return nil
	}

	devices, err := wgClient.Devices()
	if err != nil {
		collector.logCtx.WithError(err).Debug("something went wrong enumerating wireguard devices")
		err := wgClient.Close()
		if err != nil {
			collector.logCtx.WithError(err).Warn("Error from wgClient.Close.")
		}
		collector.wireguardClient = nil
		return nil
	}
	return devices
}

func (collector *Metrics) appendDeviceMetrics(devices []*wgtypes.Device, m []prometheus.Metric) []prometheus.Metric {
	collector.logCtx.Debug("collecting wg device metrics")

	for _, device := range devices {
		l := collector.defaultLabelValues(device.PublicKey.String(), deviceMetaLabelValues(device))

		collector.logCtx.WithFields(logrus.Fields{
			"dev":    device.Name,
			"labels": l,
		}).Debug("iterate device")

		m = append(m, prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				wireguardMetaFQName, wireguardMetaHelpText, nil, l,
			),
			prometheus.GaugeValue,
			1,
		))
	}
	return m
}

func (collector *Metrics) appendDevicePeerMetrics(devices []*wgtypes.Device, m []prometheus.Metric) []prometheus.Metric {
	collector.logCtx.Debug("collecting wg peer(s) metrics")

	collector.logCtx.WithFields(logrus.Fields{
		"count": len(devices),
	}).Debug("enumerated wireguard devices")

	for _, device := range devices {
		logCtx := collector.logCtx.WithFields(logrus.Fields{
			"key":  device.PublicKey,
			"name": device.Name,
		})
		for _, peer := range device.Peers {
			logCtx.WithFields(logrus.Fields{
				"peer_key":      peer.PublicKey,
				"peer_endpoint": peer.Endpoint,
			}).Debug("collect peer metrics")

			labels := collector.defaultLabelValues(device.PublicKey.String(), peerServiceLabelValues(&peer))

			hs := float64(peer.LastHandshakeTime.Unix())

			collector.logCtx.WithFields(logrus.Fields{
				"rx_bytes_total": peer.ReceiveBytes,
				"tx_bytes_total": peer.TransmitBytes,
				"handshake_ts":   hs,
			}).Debug("collected peer metrics")

			m = append(m, prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					wireguardBytesRcvdFQName, wireguardBytesRcvdHelpText, nil, labels,
				),
				prometheus.CounterValue,
				float64(peer.ReceiveBytes),
			))

			m = append(m, prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					wireguardBytesSentFQName, wireguardBytesSentHelpText, nil, labels,
				),
				prometheus.CounterValue,
				float64(peer.TransmitBytes),
			))

			m = append(m, prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					wireguardLatestHandshakeIntervalFQName, wireguardLatestHandshakeIntervalHelpText, nil, labels,
				),
				prometheus.GaugeValue,
				hs,
			))
		}
	}
	return m
}

func (collector *Metrics) defaultLabelValues(publicKey string, extend prometheus.Labels) prometheus.Labels {
	l := prometheus.Labels{labelHostname: collector.hostname}
	if publicKey != "" {
		l[labelPublicKey] = publicKey
	}

	maps.Copy(l, extend)
	return l
}

func deviceMetaLabelValues(dev *wgtypes.Device) prometheus.Labels {
	return prometheus.Labels{
		labelInterfaceName: dev.Name,
		labelListenPort:    fmt.Sprintf("%d", dev.ListenPort),
	}
}

func peerServiceLabelValues(peer *wgtypes.Peer) prometheus.Labels {
	return prometheus.Labels{
		labelPeerKey:      peer.PublicKey.String(),
		labelPeerEndpoint: peer.Endpoint.String(),
	}
}
