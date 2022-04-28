// Copyright (c) 2017, 2020 Tigera, Inc. All rights reserved.
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

package config_test

import (
	"context"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
)

func withTimeout(timeout interface{}, fn func()) func() {
	return func() {
		done := make(chan struct{})

		go func() {
			fn()
			close(done)
		}()

		EventuallyWithOffset(1, done, timeout).Should(BeClosed())
	}
}

var _ = Describe("Config", func() {

	// unsetEnv() function that unsets environment variables
	// required by kube-controllers controller
	unsetEnv := func() {
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("RECONCILER_PERIOD")
		os.Unsetenv("ENABLED_CONTROLLERS")
		os.Unsetenv("WORKLOAD_ENDPOINT_WORKERS")
		os.Unsetenv("PROFILE_WORKERS")
		os.Unsetenv("POLICY_WORKERS")
		os.Unsetenv("KUBECONFIG")
		os.Unsetenv("DATASTORE_TYPE")
		os.Unsetenv("HEALTH_ENABLED")
		os.Unsetenv("COMPACTION_PERIOD")
		os.Unsetenv("SYNC_NODE_LABELS")
		os.Unsetenv("AUTO_HOST_ENDPOINTS")
	}

	// setEnv() function that sets environment variables
	// to some sensbile values
	setEnv := func() {
		os.Setenv("LOG_LEVEL", "debug")
		os.Setenv("RECONCILER_PERIOD", "105s")
		os.Setenv("ENABLED_CONTROLLERS", "node,policy")
		os.Setenv("WORKLOAD_ENDPOINT_WORKERS", "2")
		os.Setenv("PROFILE_WORKERS", "3")
		os.Setenv("POLICY_WORKERS", "4")
		os.Setenv("KUBECONFIG", "/home/user/.kube/config")
		os.Setenv("DATASTORE_TYPE", "etcdv3")
		os.Setenv("HEALTH_ENABLED", "false")
		os.Setenv("COMPACTION_PERIOD", "33m")
		os.Setenv("SYNC_NODE_LABELS", "false")
		os.Setenv("AUTO_HOST_ENDPOINTS", "enabled")
	}

	// setWrongEnv() function sets environment variables
	// with values of wrong data type
	setWrongEnv := func() {
		os.Setenv("WORKLOAD_ENDPOINT_WORKERS", "somestring")
		os.Setenv("PROFILE_WORKERS", "somestring")
		os.Setenv("POLICY_WORKERS", "somestring")
	}

	Context("with unset env values", func() {
		var cfg *config.Config

		BeforeEach(func() {
			// Unset environment variables
			unsetEnv()
			// Parse config
			cfg = new(config.Config)
			err := cfg.Parse()
			Expect(err).ToNot(HaveOccurred())
		})

		// Assert default values
		It("should return default values", func() {
			Expect(cfg.LogLevel).To(Equal("info"))
			Expect(cfg.WorkloadEndpointWorkers).To(Equal(1))
			Expect(cfg.ProfileWorkers).To(Equal(1))
			Expect(cfg.PolicyWorkers).To(Equal(1))
			Expect(cfg.Kubeconfig).To(Equal(""))
		})

		Context("with default API values", func() {
			var m *mockKCC
			var ctrl *config.RunConfigController
			var ctx context.Context
			var cancel context.CancelFunc

			BeforeEach(func() {
				ctx, cancel = context.WithCancel(context.Background())
				m = &mockKCC{get: config.DefaultKCC.DeepCopy()}
				ctrl = config.NewRunConfigController(ctx, *cfg, m)
			})

			AfterEach(func() {
				cancel()
			})

			It("should return default RunConfig", withTimeout("1s", func() {
				runCfg := <-ctrl.ConfigChan()
				Expect(runCfg.LogLevelScreen).To(Equal(log.InfoLevel))
				Expect(runCfg.HealthEnabled).To(BeTrue())
				Expect(runCfg.EtcdV3CompactionPeriod).To(Equal(time.Minute * 10))

				rc := runCfg.Controllers
				Expect(rc.Node).To(Equal(&config.NodeControllerConfig{
					SyncLabels:        true,
					AutoHostEndpoints: false,
					DeleteNodes:       true,
					LeakGracePeriod:   &v1.Duration{Duration: 15 * time.Minute},
				}))
				Expect(rc.Policy).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Minute * 5,
					NumberOfWorkers:  1,
				}))
				Expect(rc.Namespace).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Minute * 5,
					NumberOfWorkers:  1,
				}))
				Expect(rc.WorkloadEndpoint).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Minute * 5,
					NumberOfWorkers:  1,
				}))
				Expect(rc.ServiceAccount).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Minute * 5,
					NumberOfWorkers:  1,
				}))
			}))

			It("should write status", withTimeout("1s", func() {
				<-ctrl.ConfigChan()
				Expect(m.update).ToNot(BeNil())
				s := m.update.Status
				Expect(s.EnvironmentVars).To(HaveLen(0))
				Expect(s.RunningConfig.HealthChecks).To(Equal(v3.Enabled))
				Expect(s.RunningConfig.LogSeverityScreen).To(Equal("Info"))
				Expect(s.RunningConfig.EtcdV3CompactionPeriod.Duration).To(Equal(time.Minute * 10))
				c := s.RunningConfig.Controllers
				Expect(c.Node).To(Equal(&v3.NodeControllerConfig{
					ReconcilerPeriod: nil,
					SyncLabels:       v3.Enabled,
					HostEndpoint:     &v3.AutoHostEndpointConfig{AutoCreate: v3.Disabled},
					LeakGracePeriod:  &v1.Duration{Duration: 15 * time.Minute},
				}))
				Expect(c.Policy).To(Equal(&v3.PolicyControllerConfig{
					ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 5}}))
				Expect(c.WorkloadEndpoint).To(Equal(&v3.WorkloadEndpointControllerConfig{
					ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 5}}))
				Expect(c.Namespace).To(Equal(&v3.NamespaceControllerConfig{
					ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 5}}))
				Expect(c.ServiceAccount).To(Equal(&v3.ServiceAccountControllerConfig{
					ReconcilerPeriod: &v1.Duration{Duration: time.Minute * 5}}))
			}))
		})

		Context("with non-default API values", func() {
			var m *mockKCC
			var ctrl *config.RunConfigController
			var ctx context.Context
			var cancel context.CancelFunc

			BeforeEach(func() {
				kcc := v3.NewKubeControllersConfiguration()
				kcc.Name = "default"
				kcc.Spec = v3.KubeControllersConfigurationSpec{
					LogSeverityScreen:      "Warning",
					HealthChecks:           v3.Disabled,
					EtcdV3CompactionPeriod: &v1.Duration{Duration: 0},
					Controllers: v3.ControllersConfig{
						Node: &v3.NodeControllerConfig{
							ReconcilerPeriod: nil,
							SyncLabels:       v3.Disabled,
							HostEndpoint:     &v3.AutoHostEndpointConfig{AutoCreate: v3.Enabled},
							LeakGracePeriod:  &v1.Duration{Duration: 20 * time.Minute},
						},
						Policy: &v3.PolicyControllerConfig{
							ReconcilerPeriod: &v1.Duration{Duration: time.Second * 30}},
						WorkloadEndpoint: &v3.WorkloadEndpointControllerConfig{
							ReconcilerPeriod: &v1.Duration{Duration: time.Second * 31}},
						Namespace: &v3.NamespaceControllerConfig{
							ReconcilerPeriod: &v1.Duration{Duration: time.Second * 32}},
						ServiceAccount: &v3.ServiceAccountControllerConfig{
							ReconcilerPeriod: &v1.Duration{Duration: time.Second * 33}},
					},
				}
				m = &mockKCC{get: kcc}
				ctx, cancel = context.WithCancel(context.Background())
				ctrl = config.NewRunConfigController(ctx, *cfg, m)
			})

			AfterEach(func() {
				cancel()
			})

			It("should return RunConfig matching API", withTimeout("1s", func() {
				runCfg := <-ctrl.ConfigChan()
				Expect(runCfg.LogLevelScreen).To(Equal(log.WarnLevel))
				Expect(runCfg.HealthEnabled).To(BeFalse())
				Expect(runCfg.EtcdV3CompactionPeriod).To(Equal(time.Duration(0)))

				rc := runCfg.Controllers
				Expect(rc.Node).To(Equal(&config.NodeControllerConfig{
					SyncLabels:        false,
					AutoHostEndpoints: true,
					DeleteNodes:       true,
					LeakGracePeriod:   &v1.Duration{Duration: 20 * time.Minute},
				}))
				Expect(rc.Policy).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Second * 30,
					NumberOfWorkers:  1,
				}))
				Expect(rc.WorkloadEndpoint).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Second * 31,
					NumberOfWorkers:  1,
				}))
				Expect(rc.Namespace).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Second * 32,
					NumberOfWorkers:  1,
				}))
				Expect(rc.ServiceAccount).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Second * 33,
					NumberOfWorkers:  1,
				}))
			}))

			It("should write status matching API", withTimeout("1s", func() {
				<-ctrl.ConfigChan()
				Expect(m.update).ToNot(BeNil())
				s := m.update.Status
				Expect(s.EnvironmentVars).To(HaveLen(0))

				// Since there are no environment variables, the running config
				// should be exactly the API Spec
				Expect(s.RunningConfig).To(Equal(m.get.Spec))
			}))
		})

		Context("with no API values", func() {
			var m *mockKCC
			var ctrl *config.RunConfigController
			var ctx context.Context
			var cancel context.CancelFunc

			BeforeEach(func() {
				m = &mockKCC{geterror: errors.ErrorResourceDoesNotExist{}}
				ctx, cancel = context.WithCancel(context.Background())
				ctrl = config.NewRunConfigController(ctx, *cfg, m)
			})

			AfterEach(func() {
				cancel()
			})

			It("should create a default KubeControllersConfig", withTimeout(600, func() {
				<-ctrl.ConfigChan()
				Expect(m.create.Spec).To(Equal(config.DefaultKCC.Spec))
			}))

			It("should send new update when API values change", withTimeout("1s", func() {
				// initial config
				<-ctrl.ConfigChan()

				// Wait for the watch
				Eventually(func() int { return m.watchcount }).Should(Equal(1))

				// send an update
				knew := v3.NewKubeControllersConfiguration()
				knew.Name = "default"
				knew.Spec = v3.KubeControllersConfigurationSpec{
					LogSeverityScreen: "Error",
				}
				m.watchchan <- watch.Event{
					Type:     watch.Modified,
					Previous: nil,
					Object:   knew,
					Error:    nil,
				}

				// get the update
				<-ctrl.ConfigChan()
			}))

			It("should not send new update when Spec is unchanged", withTimeout("2s", func() {
				// initial config
				<-ctrl.ConfigChan()

				// Wait for the watch
				Eventually(func() int { return m.watchcount }).Should(Equal(1))

				// send an update, containing the same thing that was created
				m.watchchan <- watch.Event{
					Type:     watch.Modified,
					Previous: nil,
					Object:   m.create,
					Error:    nil,
				}

				// we shouldn't see an update; wait 500 ms to be sure
				update := false
				a := time.After(time.Millisecond * 500)
				select {
				case <-a:
					update = false
				case <-ctrl.ConfigChan():
					update = true
				}
				Expect(update).To(BeFalse())
			}))

			It("should handle watch closed by remote", withTimeout("3s", func() {
				// initial config
				<-ctrl.ConfigChan()

				// Wait for the watch
				Eventually(func() int { return m.watchcount }).Should(Equal(1))

				// before terminating, update get to succeed the second time
				// around
				m.geterror = nil
				m.get = m.create

				// send watch error, all errors trigger a full resync.
				m.watchchan <- watch.Event{
					Type:     watch.Error,
					Previous: nil,
					Object:   nil,
					Error:    errors.ErrorDatastoreError{},
				}

				// this should not trigger an update, since the spec hasn't changed
				update := false
				a := time.After(time.Millisecond * 500)
				select {
				case <-a:
					update = false
				case <-ctrl.ConfigChan():
					update = true
				}
				Expect(update).To(BeFalse())

				// Wait for the second watch
				Eventually(func() int { return m.watchcount }).Should(Equal(2))

				// send an update on the new watch, with changed spec
				knew := v3.NewKubeControllersConfiguration()
				knew.Name = "default"
				knew.Spec = v3.KubeControllersConfigurationSpec{
					LogSeverityScreen: "Error",
				}
				m.watchchan <- watch.Event{
					Type:     watch.Modified,
					Previous: nil,
					Object:   knew,
					Error:    nil,
				}

				// this should trigger an update
				<-ctrl.ConfigChan()
			}))
		})

	})

	Context("with valid user defined values", func() {

		var cfg *config.Config

		BeforeEach(func() {
			// Set environment variables
			setEnv()

			// Parse config
			cfg = new(config.Config)
			err := cfg.Parse()

			// Assert no error generated
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			// Reset environment variables
			unsetEnv()
		})

		// Assert values
		It("shoud return user defined values", func() {
			Expect(cfg.LogLevel).To(Equal("debug"))
			Expect(cfg.WorkloadEndpointWorkers).To(Equal(2))
			Expect(cfg.ProfileWorkers).To(Equal(3))
			Expect(cfg.PolicyWorkers).To(Equal(4))
			Expect(cfg.Kubeconfig).To(Equal("/home/user/.kube/config"))
		})

		Context("with default API values", func() {
			var m *mockKCC
			var ctrl *config.RunConfigController
			var ctx context.Context
			var cancel context.CancelFunc

			BeforeEach(func() {
				ctx, cancel = context.WithCancel(context.Background())
				m = &mockKCC{get: config.DefaultKCC.DeepCopy()}
				ctrl = config.NewRunConfigController(ctx, *cfg, m)
			})

			AfterEach(func() {
				cancel()
			})

			It("should return RunConfig matching env", withTimeout("600s", func() {
				runCfg := <-ctrl.ConfigChan()
				Expect(runCfg.LogLevelScreen).To(Equal(log.DebugLevel))
				Expect(runCfg.HealthEnabled).To(BeFalse())
				Expect(runCfg.EtcdV3CompactionPeriod).To(Equal(time.Minute * 33))

				rc := runCfg.Controllers
				Expect(rc.Node).To(Equal(&config.NodeControllerConfig{
					SyncLabels:        false,
					AutoHostEndpoints: true,
					DeleteNodes:       true,
					LeakGracePeriod:   &v1.Duration{Duration: 15 * time.Minute},
				}))
				Expect(rc.Policy).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Second * 105,
					NumberOfWorkers:  4,
				}))
				Expect(rc.Namespace).To(BeNil())
				Expect(rc.WorkloadEndpoint).To(BeNil())
				Expect(rc.ServiceAccount).To(BeNil())
			}))

			It("should write status", withTimeout("1s", func() {
				<-ctrl.ConfigChan()
				Expect(m.update).ToNot(BeNil())
				s := m.update.Status
				Expect(s.EnvironmentVars).To(Equal(map[string]string{
					"LOG_LEVEL":           "debug",
					"RECONCILER_PERIOD":   "105s",
					"ENABLED_CONTROLLERS": "node,policy",
					"HEALTH_ENABLED":      "false",
					"COMPACTION_PERIOD":   "33m",
					"SYNC_NODE_LABELS":    "false",
					"AUTO_HOST_ENDPOINTS": "enabled",
				}))
				Expect(s.RunningConfig.HealthChecks).To(Equal(v3.Disabled))
				Expect(s.RunningConfig.LogSeverityScreen).To(Equal("Debug"))
				Expect(s.RunningConfig.EtcdV3CompactionPeriod.Duration).To(Equal(time.Minute * 33))
				c := s.RunningConfig.Controllers
				Expect(c.Node).To(Equal(&v3.NodeControllerConfig{
					ReconcilerPeriod: nil,
					SyncLabels:       v3.Disabled,
					HostEndpoint:     &v3.AutoHostEndpointConfig{AutoCreate: v3.Enabled},
					LeakGracePeriod:  &v1.Duration{Duration: 15 * time.Minute},
				}))
				Expect(c.Policy).To(Equal(&v3.PolicyControllerConfig{
					ReconcilerPeriod: &v1.Duration{Duration: time.Second * 105}}))
				Expect(c.WorkloadEndpoint).To(BeNil())
				Expect(c.Namespace).To(BeNil())
				Expect(c.ServiceAccount).To(BeNil())
			}))
		})

		Context("with non-default API values", func() {
			var m *mockKCC
			var ctrl *config.RunConfigController
			var ctx context.Context
			var cancel context.CancelFunc

			BeforeEach(func() {
				kcc := v3.NewKubeControllersConfiguration()
				kcc.Name = "default"
				kcc.Spec = v3.KubeControllersConfigurationSpec{
					LogSeverityScreen:      "Warning",
					HealthChecks:           v3.Enabled,
					EtcdV3CompactionPeriod: &v1.Duration{Duration: 0},
					Controllers: v3.ControllersConfig{
						Node: &v3.NodeControllerConfig{
							ReconcilerPeriod: nil,
							SyncLabels:       v3.Disabled,
							HostEndpoint:     &v3.AutoHostEndpointConfig{AutoCreate: v3.Enabled},
						},
						Policy: &v3.PolicyControllerConfig{
							ReconcilerPeriod: &v1.Duration{Duration: time.Second * 30}},
						WorkloadEndpoint: &v3.WorkloadEndpointControllerConfig{
							ReconcilerPeriod: &v1.Duration{Duration: time.Second * 31}},
						Namespace: &v3.NamespaceControllerConfig{
							ReconcilerPeriod: &v1.Duration{Duration: time.Second * 32}},
						ServiceAccount: &v3.ServiceAccountControllerConfig{
							ReconcilerPeriod: &v1.Duration{Duration: time.Second * 33}},
					},
				}
				m = &mockKCC{get: kcc}
				ctx, cancel = context.WithCancel(context.Background())
				ctrl = config.NewRunConfigController(ctx, *cfg, m)
			})

			AfterEach(func() {
				cancel()
			})

			It("should return RunConfig matching API environment", withTimeout("1s", func() {
				runCfg := <-ctrl.ConfigChan()
				Expect(runCfg.LogLevelScreen).To(Equal(log.DebugLevel))
				Expect(runCfg.HealthEnabled).To(BeFalse())
				Expect(runCfg.EtcdV3CompactionPeriod).To(Equal(time.Minute * 33))

				rc := runCfg.Controllers
				Expect(rc.Node).To(Equal(&config.NodeControllerConfig{
					SyncLabels:        false,
					AutoHostEndpoints: true,
					DeleteNodes:       true,
				}))
				Expect(rc.Policy).To(Equal(&config.GenericControllerConfig{
					ReconcilerPeriod: time.Second * 105,
					NumberOfWorkers:  4,
				}))
				Expect(rc.WorkloadEndpoint).To(BeNil())
				Expect(rc.Namespace).To(BeNil())
				Expect(rc.ServiceAccount).To(BeNil())
			}))

			It("should write status matching environment", withTimeout("1s", func() {
				<-ctrl.ConfigChan()
				Expect(m.update).ToNot(BeNil())
				s := m.update.Status
				Expect(s.EnvironmentVars).To(Equal(map[string]string{
					"LOG_LEVEL":           "debug",
					"RECONCILER_PERIOD":   "105s",
					"ENABLED_CONTROLLERS": "node,policy",
					"HEALTH_ENABLED":      "false",
					"COMPACTION_PERIOD":   "33m",
					"SYNC_NODE_LABELS":    "false",
					"AUTO_HOST_ENDPOINTS": "enabled",
				}))
				Expect(s.RunningConfig.HealthChecks).To(Equal(v3.Disabled))
				Expect(s.RunningConfig.LogSeverityScreen).To(Equal("Debug"))
				Expect(s.RunningConfig.EtcdV3CompactionPeriod.Duration).To(Equal(time.Minute * 33))
				c := s.RunningConfig.Controllers
				Expect(c.Node).To(Equal(&v3.NodeControllerConfig{
					ReconcilerPeriod: nil,
					SyncLabels:       v3.Disabled,
					HostEndpoint:     &v3.AutoHostEndpointConfig{AutoCreate: v3.Enabled},
				}))
				Expect(c.Policy).To(Equal(&v3.PolicyControllerConfig{
					ReconcilerPeriod: &v1.Duration{Duration: time.Second * 105}}))
				Expect(c.WorkloadEndpoint).To(BeNil())
				Expect(c.Namespace).To(BeNil())
				Expect(c.ServiceAccount).To(BeNil())
			}))
		})

	})

	Context("with invalid user defined values", func() {
		var cfg *config.Config

		BeforeEach(func() {
			// Set wrong environment variables
			setWrongEnv()
		})

		AfterEach(func() {
			// Reset environment variables
			unsetEnv()
		})

		// Assert error is generated
		It("shoud generate error", func() {
			// Parse config
			cfg = new(config.Config)
			err := cfg.Parse()
			Expect(err).To(HaveOccurred())
		})
	})

	Context("with ENABLED_CONTROLLERS set", func() {

		BeforeEach(func() {
			unsetEnv()
			err := os.Setenv("ENABLED_CONTROLLERS", "node,namespace,policy,serviceaccount,workloadendpoint")
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			unsetEnv()
		})

		It("should use reconciler periods from API", withTimeout("1s", func() {

			cfg := new(config.Config)
			err := cfg.Parse()
			Expect(err).ToNot(HaveOccurred())
			kcc := v3.NewKubeControllersConfiguration()
			kcc.Name = "default"
			kcc.Spec = v3.KubeControllersConfigurationSpec{
				LogSeverityScreen:      "Warning",
				HealthChecks:           v3.Enabled,
				EtcdV3CompactionPeriod: &v1.Duration{Duration: 0},
				Controllers: v3.ControllersConfig{
					Node: &v3.NodeControllerConfig{
						ReconcilerPeriod: &v1.Duration{Duration: time.Second * 29},
						SyncLabels:       v3.Disabled,
						HostEndpoint:     &v3.AutoHostEndpointConfig{AutoCreate: v3.Enabled},
					},
					Policy: &v3.PolicyControllerConfig{
						ReconcilerPeriod: &v1.Duration{Duration: time.Second * 30}},
					WorkloadEndpoint: &v3.WorkloadEndpointControllerConfig{
						ReconcilerPeriod: &v1.Duration{Duration: time.Second * 31}},
					Namespace: &v3.NamespaceControllerConfig{
						ReconcilerPeriod: &v1.Duration{Duration: time.Second * 32}},
					ServiceAccount: &v3.ServiceAccountControllerConfig{
						ReconcilerPeriod: &v1.Duration{Duration: time.Second * 33}},
				},
			}
			m := &mockKCC{get: kcc}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctrl := config.NewRunConfigController(ctx, *cfg, m)
			runCfg := <-ctrl.ConfigChan()
			Expect(runCfg.Controllers.Policy.ReconcilerPeriod).To(Equal(time.Second * 30))
			Expect(runCfg.Controllers.WorkloadEndpoint.ReconcilerPeriod).To(Equal(time.Second * 31))
			Expect(runCfg.Controllers.Namespace.ReconcilerPeriod).To(Equal(time.Second * 32))
			Expect(runCfg.Controllers.ServiceAccount.ReconcilerPeriod).To(Equal(time.Second * 33))
		}))
	})
})

type mockKCC struct {
	get        *v3.KubeControllersConfiguration
	geterror   error
	update     *v3.KubeControllersConfiguration
	create     *v3.KubeControllersConfiguration
	watchchan  chan watch.Event
	watchcount int
}

func (m *mockKCC) Create(ctx context.Context, res *v3.KubeControllersConfiguration, opts options.SetOptions) (*v3.KubeControllersConfiguration, error) {
	m.create = res
	return res, nil
}

func (m *mockKCC) Update(ctx context.Context, res *v3.KubeControllersConfiguration, opts options.SetOptions) (*v3.KubeControllersConfiguration, error) {
	m.update = res.DeepCopy()
	return res, nil
}

func (m *mockKCC) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*v3.KubeControllersConfiguration, error) {
	panic("implement me")
}

func (m *mockKCC) Get(ctx context.Context, name string, opts options.GetOptions) (*v3.KubeControllersConfiguration, error) {
	return m.get, m.geterror
}

func (m *mockKCC) List(ctx context.Context, opts options.ListOptions) (*v3.KubeControllersConfigurationList, error) {
	kccs := []v3.KubeControllersConfiguration{}
	if m.get != nil {
		kccs = append(kccs, *m.get)
	}
	return &v3.KubeControllersConfigurationList{
		Items: kccs,
	}, nil
}

func (m *mockKCC) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	m.watchchan = make(chan watch.Event)
	m.watchcount++
	return &mockWatch{r: m.watchchan}, nil
}

type mockWatch struct {
	r         chan watch.Event
	stopcount int
}

func (m *mockWatch) Stop() {
	m.stopcount += 1
}

func (m *mockWatch) ResultChan() <-chan watch.Event {
	return m.r
}
