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

package logcollector_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/logcollector"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// TestRenderedConfigGoldens pins the full fluent-bit configuration the
// operator renders for the scenarios fluentd's config test harness
// (calico-private fluentd/test/test.sh) used to cover, one golden file per
// scenario under testdata/rendered-configs/. Each table entry names the
// test.sh case it descends from; testdata/rendered-configs/README.md maps
// every test.sh case (including the retired Elasticsearch ones) to its golden
// here.
//
// To regenerate after an intentional rendering change:
//
//	UPDATE_RENDERED_CONFIGS=1 go test ./pkg/render/logcollector/ -run TestRenderedConfigGoldens
func TestRenderedConfigGoldens(t *testing.T) {
	nonClusterOnly := operatorv1.HostScopeNonClusterOnly

	// Store specs mirror the values test.sh used, so the goldens read
	// side-by-side with the fluentd golden .cfg files.
	s3Spec := func(scope *operatorv1.HostScope) *operatorv1.S3StoreSpec {
		return &operatorv1.S3StoreSpec{
			Region:     "not-real-region",
			BucketName: "dummy-bucket",
			BucketPath: "not-a-bucket",
			HostScope:  scope,
		}
	}
	// SYSLOG_TLS_VARS: flows + kube audit + IDS events over tcp/TLS. The
	// operator's Audit type always enables both audit.tsee and audit.kube
	// (fluentd's SYSLOG_AUDIT_EE_LOG/SYSLOG_AUDIT_KUBE_LOG have no separate
	// CRD knobs), so audit.tsee appears here where the fluentd golden had
	// kube-audit only.
	syslogTLSSpec := func(logTypes []operatorv1.SyslogLogType, scope *operatorv1.HostScope) *operatorv1.SyslogStoreSpec {
		return &operatorv1.SyslogStoreSpec{
			Endpoint:   "tcp://169.254.254.254:3665",
			LogTypes:   logTypes,
			Encryption: operatorv1.EncryptionTLS,
			HostScope:  scope,
		}
	}
	syslogTLSTypes := []operatorv1.SyslogLogType{
		operatorv1.SyslogLogFlows, operatorv1.SyslogLogAudit, operatorv1.SyslogLogIDSEvents,
	}
	// The CRD's full enum; fluentd's all-log-types case additionally set the
	// L7/runtime/WAF env toggles, which the operator API never exposed.
	syslogAllTypes := []operatorv1.SyslogLogType{
		operatorv1.SyslogLogAudit, operatorv1.SyslogLogDNS,
		operatorv1.SyslogLogFlows, operatorv1.SyslogLogIDSEvents,
	}
	eksConfig := func(streamPrefix string) *logcollector.EksCloudwatchLogConfig {
		return &logcollector.EksCloudwatchLogConfig{
			AwsId:         []byte("aws-key-id-value"),
			AwsKey:        []byte("aws-secret-key-value"),
			AwsRegion:     "not-real-region",
			GroupName:     "/aws/eks/eks-audit-test/cluster/",
			StreamPrefix:  streamPrefix,
			FetchInterval: 10,
		}
	}

	scenarios := []struct {
		name        string
		fluentdCase string // the fluentd test.sh case this descends from
		configure   func(cfg *logcollector.FluentBitConfiguration)
		eks         bool         // golden the eks-log-forwarder config instead of the daemonset config
		osType      rmeta.OSType // OS to render; defaults to Linux when empty
	}{
		{
			name:        "linseed",
			fluentdCase: "linseed",
			configure:   func(cfg *logcollector.FluentBitConfiguration) {},
		},
		{
			name:        "linseed-nch",
			fluentdCase: "linseed (the fluentd http source was always rendered; fluent-bit gates it on NonClusterHost)",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.NonClusterHost = &operatorv1.NonClusterHost{
					ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
					Spec:       operatorv1.NonClusterHostSpec{Endpoint: "https://1.2.3.4:5678"},
				}
			},
		},
		{
			name:        "s3",
			fluentdCase: "es-secure-with-s3",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{S3: s3Spec(nil)}
			},
		},
		{
			name:        "s3-non-cluster-only",
			fluentdCase: "es-secure-with-s3-nch",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{S3: s3Spec(&nonClusterOnly)}
			},
		},
		{
			name:        "syslog-no-tls",
			fluentdCase: "es-no-secure-with-syslog-no-tls",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					Syslog: &operatorv1.SyslogStoreSpec{
						Endpoint: "udp://169.254.254.254:3665",
						LogTypes: []operatorv1.SyslogLogType{operatorv1.SyslogLogFlows},
					},
				}
			},
		},
		{
			name:        "syslog-tls",
			fluentdCase: "es-secure-with-syslog-with-tls",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.UseSyslogCertificate = true
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					Syslog: syslogTLSSpec(syslogTLSTypes, nil),
				}
			},
		},
		{
			name:        "syslog-tls-all-log-types",
			fluentdCase: "es-secure-with-syslog-with-tls-all-log-types",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.UseSyslogCertificate = true
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					Syslog: syslogTLSSpec(syslogAllTypes, nil),
				}
			},
		},
		{
			name:        "syslog-tls-non-cluster-only",
			fluentdCase: "es-secure-with-syslog-with-tls-nch",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.UseSyslogCertificate = true
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					Syslog: syslogTLSSpec(syslogTLSTypes, &nonClusterOnly),
				}
			},
		},
		{
			name:        "syslog-tls-all-log-types-non-cluster-only",
			fluentdCase: "es-secure-with-syslog-with-tls-all-log-types-nch",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.UseSyslogCertificate = true
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					Syslog: syslogTLSSpec(syslogAllTypes, &nonClusterOnly),
				}
			},
		},
		{
			name:        "syslog-and-s3",
			fluentdCase: "es-secure-with-syslog-and-s3",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.UseSyslogCertificate = true
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					S3:     s3Spec(nil),
					Syslog: syslogTLSSpec(syslogTLSTypes, nil),
				}
			},
		},
		{
			name:        "syslog-and-s3-non-cluster-only",
			fluentdCase: "es-secure-with-syslog-and-s3-nch",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.UseSyslogCertificate = true
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					S3:     s3Spec(&nonClusterOnly),
					Syslog: syslogTLSSpec(syslogTLSTypes, &nonClusterOnly),
				}
			},
		},
		{
			name:        "splunk-https",
			fluentdCase: "splunk-trusted-http-https (https endpoint)",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					Splunk: &operatorv1.SplunkStoreSpec{Endpoint: "https://splunk.eng.tigera.com:8088"},
				}
			},
		},
		{
			name:        "splunk-http",
			fluentdCase: "splunk-trusted-http-https (http endpoint)",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					Splunk: &operatorv1.SplunkStoreSpec{Endpoint: "http://splunk.eng.tigera.com:8088"},
				}
			},
		},
		{
			name:        "splunk-non-cluster-only",
			fluentdCase: "splunk-trusted-http-https-nch",
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.LogCollector.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
					Splunk: &operatorv1.SplunkStoreSpec{
						Endpoint:  "https://splunk.eng.tigera.com:8088",
						HostScope: &nonClusterOnly,
					},
				}
			},
		},
		{
			name:        "eks",
			fluentdCase: "eks",
			eks:         true,
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.EKSConfig = eksConfig("kube-apiserver-audit-")
			},
		},
		{
			name:        "eks-log-stream-prefix",
			fluentdCase: "eks-log-stream-pfx",
			eks:         true,
			configure: func(cfg *logcollector.FluentBitConfiguration) {
				cfg.EKSConfig = eksConfig("kube-apiserver-audit-overwritten-")
			},
		},
		{
			name:        "windows",
			fluentdCase: "(none — reviewability golden for the Windows daemonset config)",
			osType:      rmeta.OSTypeWindows,
			configure:   func(cfg *logcollector.FluentBitConfiguration) {},
		},
	}

	update := os.Getenv("UPDATE_RENDERED_CONFIGS") == "1"
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			cfg := goldenBaseConfig(t)
			sc.configure(cfg)

			osType := sc.osType
			if osType == "" {
				osType = rmeta.OSTypeLinux
			}
			resources, _ := logcollector.FluentBitOSSpecific(cfg, osType).Objects()
			cmName := logcollector.FluentBitConfConfigMapName
			if osType == rmeta.OSTypeWindows {
				cmName += "-windows"
			}
			if sc.eks {
				cmName = logcollector.EKSLogForwarderConfConfigMapName
			}
			obj := rtest.GetResource(resources, cmName, render.LogCollectorNamespace, "", "v1", "ConfigMap")
			if obj == nil {
				t.Fatalf("ConfigMap %s not rendered", cmName)
			}
			rendered := obj.(*corev1.ConfigMap).Data["fluent-bit.yaml"]
			if rendered == "" {
				t.Fatalf("ConfigMap %s has no fluent-bit.yaml content", cmName)
			}

			goldenPath := filepath.Join("testdata", "rendered-configs", sc.name+".yaml")
			if update {
				if err := os.WriteFile(goldenPath, []byte(rendered), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("missing golden (run with UPDATE_RENDERED_CONFIGS=1 to generate): %v", err)
			}
			if rendered != string(want) {
				t.Errorf("rendered config differs from %s (fluentd test.sh case: %s)\n%s\nTo accept an intentional change: UPDATE_RENDERED_CONFIGS=1 go test ./pkg/render/logcollector/ -run TestRenderedConfigGoldens",
					goldenPath, sc.fluentdCase, firstDiff(string(want), rendered))
			}
		})
	}
}

// goldenBaseConfig mirrors the ginkgo suite's BeforeEach: a default Linux
// FluentBitConfiguration with operator-CA keypairs and trusted bundle. All
// paths referenced by the rendered config are fixed mount paths, so the
// output is byte-stable.
func goldenBaseConfig(t *testing.T) *logcollector.FluentBitConfiguration {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := apis.AddToScheme(scheme, false); err != nil {
		t.Fatal(err)
	}
	cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
	certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	if err != nil {
		t.Fatal(err)
	}
	metricsSecret, err := certificateManager.GetOrCreateKeyPair(cli, logcollector.FluentBitTLSSecretName, common.OperatorNamespace(), []string{""})
	if err != nil {
		t.Fatal(err)
	}
	eksSecret, err := certificateManager.GetOrCreateKeyPair(cli, logcollector.EKSLogForwarderTLSSecretName, common.OperatorNamespace(), []string{""})
	if err != nil {
		t.Fatal(err)
	}
	return &logcollector.FluentBitConfiguration{
		LogCollector:  &operatorv1.LogCollector{},
		ClusterDomain: dns.DefaultClusterDomain,
		Installation: &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
		},
		FluentBitKeyPair:       metricsSecret,
		EKSLogForwarderKeyPair: eksSecret,
		TrustedBundle:          certificatemanagement.CreateNamedTrustedBundle(render.FluentBitNodeName, certificateManager.KeyPair(), true),
	}
}

// firstDiff returns a hint at the first line where want and got diverge.
func firstDiff(want, got string) string {
	wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w != g {
			return fmt.Sprintf("first difference at line %d:\n  golden: %q\n  got:    %q", i+1, w, g)
		}
	}
	return "contents differ (no line-level difference found)"
}
