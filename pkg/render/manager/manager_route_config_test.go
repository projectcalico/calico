// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package manager_test

import (
	"bytes"
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render/manager"
)

var _ = Describe("VoltronRouteConfigBuilder", func() {
	var (
		builder manager.VoltronRouteConfigBuilder

		route                      operatorv1.TLSTerminatedRoute
		routesConfigMapVolumeMount corev1.VolumeMount
		routesConfigMapVolume      corev1.Volume
		routesConfigMap            *corev1.ConfigMap

		caBundle            *corev1.ConfigMap
		caBundleVolumeMount corev1.VolumeMount
		caBundleVolume      corev1.Volume

		mtlsCert *corev1.Secret
		mtlsKey  *corev1.Secret

		mtlsCertVolumeMount corev1.VolumeMount
		mtlsCertVolume      corev1.Volume

		mtlsKeyVolumeMount corev1.VolumeMount
		mtlsKeyVolume      corev1.Volume
	)

	BeforeEach(func() {
		builder = manager.NewVoltronRouteConfigBuilder()

		route = operatorv1.TLSTerminatedRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "tigera-manager"},
			Spec: operatorv1.TLSTerminatedRouteSpec{
				PathMatch: &operatorv1.PathMatch{
					Path:        "/foobar",
					PathRegexp:  ptr.To("^/foobar$"),
					PathReplace: ptr.To("/"),
				},
			},
		}

		routesConfigMapVolumeMount = corev1.VolumeMount{
			Name: "cm-voltron-routes", MountPath: "/config_maps/voltron-routes", ReadOnly: true,
		}

		routesConfigMapVolume = corev1.Volume{
			Name: "cm-voltron-routes",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "voltron-routes"},
					DefaultMode:          ptr.To(int32(420)),
				},
			},
		}

		routesConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "voltron-routes", Namespace: "tigera-manager"},
			Data:       map[string]string{},
		}

		caBundle = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Data: map[string]string{
				"bundle": "bundle",
			},
		}

		caBundleVolumeMount = corev1.VolumeMount{Name: "cm-ca-bundle", MountPath: "/config_maps/ca-bundle", ReadOnly: true}
		caBundleVolume = corev1.Volume{
			Name: "cm-ca-bundle",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "ca-bundle"},
					DefaultMode:          ptr.To(int32(420)),
				},
			},
		}

		mtlsCert = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mtls-cert",
				Namespace: "tigera-manager",
			},
			Data: map[string][]byte{
				"cert.pem": []byte("certbytes"),
			},
		}

		mtlsCertVolumeMount = corev1.VolumeMount{Name: "scrt-mtls-cert", MountPath: "/secrets/mtls-cert", ReadOnly: true}
		mtlsCertVolume = corev1.Volume{
			Name: "scrt-mtls-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  mtlsCert.Name,
					DefaultMode: ptr.To(int32(420)),
				},
			},
		}

		mtlsKey = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mtls-key",
				Namespace: "tigera-manager",
			},
			Data: map[string][]byte{
				"key.pem": []byte("keybytes"),
			},
		}

		mtlsKeyVolumeMount = corev1.VolumeMount{Name: "scrt-mtls-key", MountPath: "/secrets/mtls-key", ReadOnly: true}

		mtlsKeyVolume = corev1.Volume{
			Name: "scrt-mtls-key",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  mtlsKey.Name,
					DefaultMode: ptr.To(int32(420)),
				},
			},
		}
	})

	Context("TLSTerminatedRoutes", func() {
		When("the CABundle is not set", func() {
			It("returns an error", func() {
				builder.AddTLSTerminatedRoute(route)

				_, err := builder.Build()
				Expect(err).Should(HaveOccurred())
			})
		})

		When("the CABundle is set but the config map was not added to the builder", func() {
			It("returns an error", func() {
				route.Spec.CABundle = &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "ca-bundle",
					},
					Key: "ca.bundle",
				}
				builder.AddTLSTerminatedRoute(route)

				_, err := builder.Build()
				Expect(err).Should(HaveOccurred())
			})
		})

		When("two configmap entries result in the same annotation value", func() {
			It("resolves the conflict by creating a different annotation key for the second conflicting value", func() {
				mtlsCert = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "verylongnametoforceconflictlogic",
						Namespace: "tigera-manager",
					},
					Data: map[string][]byte{},
				}

				// Add enough routes with different keys from the same config map to force the conflict to go above 10,
				// so we can test that we don't go over the 63 char limit when the number of digits increase for the suffix.
				num := 6
				for i := 0; i < num; i++ {
					mtlsCert.Data[fmt.Sprintf("%s%d", "cert.pem", i)] = []byte("bytes")
					mtlsCert.Data[fmt.Sprintf("%s%d", "key.pem", i)] = []byte("bytes")
					route := operatorv1.TLSTerminatedRoute{
						ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%d-test-route", i), Namespace: "tigera-manager"},
						Spec: operatorv1.TLSTerminatedRouteSpec{
							PathMatch: &operatorv1.PathMatch{
								Path:        fmt.Sprintf("/foobar-%d", num-1-i),
								PathRegexp:  ptr.To("^/foobar$"),
								PathReplace: ptr.To("/"),
							},
						},
					}

					route.Spec.CABundle = &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "ca-bundle",
						},
						Key: "ca.bundle",
					}

					route.Spec.Target = operatorv1.TargetTypeUI
					route.Spec.ForwardingMTLSCert = &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: mtlsCert.Name,
						},
						Key: fmt.Sprintf("%s%d", "cert.pem", i),
					}
					route.Spec.ForwardingMTLSKey = &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: mtlsCert.Name,
						},
						Key: fmt.Sprintf("%s%d", "key.pem", i),
					}

					builder.AddTLSTerminatedRoute(route)
				}

				builder.AddConfigMap(caBundle)
				builder.AddSecret(mtlsCert)
				builder.AddSecret(mtlsKey)

				config, err := builder.Build()
				Expect(err).ShouldNot(HaveOccurred())

				Expect(config.Annotations()).Should(Equal(map[string]string{
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflict": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic1": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic2": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic3": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic4": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic5": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic6": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic7": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic8": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconflic9": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconfli10": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-s-verylongnametoforceconfli11": "b64f683d0e588b7b03b62f62460efd553df9491e",
					"hash.operator.tigera.io/routeconf-cm-ca-bundle-bundle":           "ed2e97c745074a9d7ed51a99ea4dfb8b337a3109",
					"hash.operator.tigera.io/routeconf-cm-voltron-routes-uitlstermro": "05f3ffd328b6f86f89a9fb6814b6d2a8d8b12299",
				}))
			})
		})

		When("the CABundle is set and the config map was added to the builder", func() {
			DescribeTable("successfully builds the config", func(target operatorv1.TargetType, fileName string, routeCMKey string) {
				route.Spec.Target = target
				route.Spec.CABundle = &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "ca-bundle",
					},
					Key: "ca.bundle",
				}

				builder.AddTLSTerminatedRoute(route)

				builder.AddConfigMap(caBundle)

				config, err := builder.Build()
				Expect(err).ShouldNot(HaveOccurred())

				Expect(config.Annotations()).Should(Equal(map[string]string{
					"hash.operator.tigera.io/routeconf-cm-ca-bundle-bundle": "ed2e97c745074a9d7ed51a99ea4dfb8b337a3109",
					routeCMKey: "ca2304ee9ca1739c7efdb1b2fc30a348041576c7",
				}))
				Expect(config.VolumeMounts()).Should(Equal([]corev1.VolumeMount{caBundleVolumeMount, routesConfigMapVolumeMount}))

				Expect(config.Volumes()).Should(Equal([]corev1.Volume{caBundleVolume, routesConfigMapVolume}))

				cm := config.RoutesConfigMap("tigera-manager")
				cm.Data[fileName] = compactJSONString(cm.Data[fileName])

				routesConfigMap.Data[fileName] = `[{"destination":"","path":"/foobar","caBundlePath":"/config_maps/ca-bundle/ca.bundle","pathRegexp":"^/foobar$","pathReplace":"/"}]`
				Expect(cm).Should(Equal(routesConfigMap))
			},
				Entry("UI target", operatorv1.TargetTypeUI, "uiTLSTermRoutes.json", "hash.operator.tigera.io/routeconf-cm-voltron-routes-uitlstermro"),
				Entry("Upstream tunnel target", operatorv1.TargetTypeUpstreamTunnel, "upTunTLSTermRoutes.json", "hash.operator.tigera.io/routeconf-cm-voltron-routes-uptuntlster"),
			)
		})

		When("the MTLS cert is specified", func() {
			BeforeEach(func() {
				route.Spec.CABundle = &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "ca-bundle",
					},
					Key: "ca.bundle",
				}
			})

			It("returns an error if the MTLS key is not specified", func() {
				route.Spec.Target = operatorv1.TargetTypeUI
				route.Spec.ForwardingMTLSCert = &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: mtlsCert.Name,
					},
					Key: "cert.pem",
				}

				builder.AddTLSTerminatedRoute(route)
				builder.AddConfigMap(caBundle)
				builder.AddSecret(mtlsCert)

				_, err := builder.Build()
				Expect(err).Should(HaveOccurred())
			})

			DescribeTable("succeeds if the MTLS key is specified", func(target operatorv1.TargetType, fileName string, routeCMKey string) {
				route.Spec.Target = target
				route.Spec.ForwardingMTLSCert = &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: mtlsCert.Name,
					},
					Key: "cert.pem",
				}
				route.Spec.ForwardingMTLSKey = &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: mtlsKey.Name,
					},
					Key: "key.pem",
				}

				builder.AddTLSTerminatedRoute(route)
				builder.AddConfigMap(caBundle)
				builder.AddSecret(mtlsCert)
				builder.AddSecret(mtlsKey)

				config, err := builder.Build()
				Expect(err).ShouldNot(HaveOccurred())

				Expect(config.Annotations()).Should(Equal(map[string]string{
					"hash.operator.tigera.io/routeconf-cm-ca-bundle-bundle":  "ed2e97c745074a9d7ed51a99ea4dfb8b337a3109",
					"hash.operator.tigera.io/routeconf-s-mtls-cert-cert.pem": "e50bc7ce05be499174194858aaf077b556de4d4a",
					"hash.operator.tigera.io/routeconf-s-mtls-key-key.pem":   "6b519c7eea53167b5fe03c86b7650ada4e7a4784",
					routeCMKey: "89372dff23323c2dc393016ffa370df893ec0dd7",
				}))
				Expect(config.VolumeMounts()).Should(Equal([]corev1.VolumeMount{caBundleVolumeMount, routesConfigMapVolumeMount, mtlsCertVolumeMount, mtlsKeyVolumeMount}))

				Expect(config.Volumes()).Should(Equal([]corev1.Volume{caBundleVolume, routesConfigMapVolume, mtlsCertVolume, mtlsKeyVolume}))

				cm := config.RoutesConfigMap("tigera-manager")
				cm.Data[fileName] = compactJSONString(cm.Data[fileName])

				routesConfigMap.Data[fileName] = `[{"destination":"","path":"/foobar","caBundlePath":"/config_maps/ca-bundle/ca.bundle","pathRegexp":"^/foobar$","pathReplace":"/","clientCertPath":"/secrets/mtls-cert/cert.pem","clientKeyPath":"/secrets/mtls-key/key.pem"}]`
				Expect(cm).Should(Equal(routesConfigMap))
			},
				Entry("UI target", operatorv1.TargetTypeUI, "uiTLSTermRoutes.json", "hash.operator.tigera.io/routeconf-cm-voltron-routes-uitlstermro"),
				Entry("Upstream tunnel target", operatorv1.TargetTypeUpstreamTunnel, "upTunTLSTermRoutes.json", "hash.operator.tigera.io/routeconf-cm-voltron-routes-uptuntlster"),
			)
		})

		When("adding multiple routes out of order", func() {
			It("volume and volume mounts should be sorted", func() {
				routes := []operatorv1.TLSTerminatedRoute{
					{
						TypeMeta:   metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{Name: "route-2"},
						Spec: operatorv1.TLSTerminatedRouteSpec{
							Target: operatorv1.TargetTypeUI,
							CABundle: &corev1.ConfigMapKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "ca-bundle",
								},
								Key: "ca-bundle.crt",
							},
							PathMatch: &operatorv1.PathMatch{
								Path:        "/bar/",
								PathRegexp:  ptr.To("^/bar/?"),
								PathReplace: ptr.To("/"),
							},
							Destination: "bar",
						},
					},
					{
						TypeMeta:   metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{Name: "route-1"},
						Spec: operatorv1.TLSTerminatedRouteSpec{
							Target: operatorv1.TargetTypeUI,
							CABundle: &corev1.ConfigMapKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "public-cert",
								},
								Key: "tls.crt",
							},
							PathMatch: &operatorv1.PathMatch{
								Path:        "/foo/",
								PathRegexp:  ptr.To("^/foo/?"),
								PathReplace: ptr.To("/"),
							},
							Destination: "foo",
						},
					},
					{
						TypeMeta:   metav1.TypeMeta{},
						ObjectMeta: metav1.ObjectMeta{Name: "route-3"},
						Spec: operatorv1.TLSTerminatedRouteSpec{
							Target: operatorv1.TargetTypeUI,
							CABundle: &corev1.ConfigMapKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "ca-bundle",
								},
								Key: "ca-bundle.crt",
							},
							PathMatch: &operatorv1.PathMatch{
								Path:        "/goo/",
								PathRegexp:  ptr.To("^/goo/?"),
								PathReplace: ptr.To("/"),
							},
							Destination: "goo",
						},
					},
				}
				for _, route := range routes {
					builder.AddTLSTerminatedRoute(route)
				}

				builder.AddConfigMap(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name: "public-cert",
					},
					Data: map[string]string{
						"tls.crt": "bundle",
					},
				})
				builder.AddConfigMap(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name: "ca-bundle",
					},
					Data: map[string]string{
						"ca-bundle.crt": "bundle",
					},
				})
				config, err := builder.Build()
				Expect(err).ShouldNot(HaveOccurred())

				Expect(config.VolumeMounts()).Should(Equal([]corev1.VolumeMount{
					{
						Name:      "cm-ca-bundle",
						MountPath: "/config_maps/ca-bundle",
						ReadOnly:  true,
					},
					{
						Name:      "cm-public-cert",
						MountPath: "/config_maps/public-cert",
						ReadOnly:  true,
					},
					{
						Name:      "cm-voltron-routes",
						MountPath: "/config_maps/voltron-routes",
						ReadOnly:  true,
					},
				}))

			})
		})
	})
})

func compactJSONString(jsonStr string) string {
	buffer := new(bytes.Buffer)
	ExpectWithOffset(1, json.Compact(buffer, []byte(jsonStr))).ShouldNot(HaveOccurred())
	return buffer.String()
}
