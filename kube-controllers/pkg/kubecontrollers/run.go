// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
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

package kubecontrollers

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/projectcalico/api/pkg/client/informers_generated/externalversions"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/client/pkg/v3/srv"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"k8s.io/apiserver/pkg/storage/etcd3"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/flannelmigration"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/ippool"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/loadbalancer"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/namespace"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/networkpolicy"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/node"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/pod"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/serviceaccount"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/tier"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	"github.com/projectcalico/calico/kube-controllers/pkg/status"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/debugserver"
	"github.com/projectcalico/calico/libcalico-go/lib/kubevirt"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
	"github.com/projectcalico/calico/pkg/cmdwrapper"
)

// Run is the main entry point for the kube-controllers daemon. It configures klog,
// loads configuration, initializes the datastore, starts all configured controllers,
// and blocks until a config change triggers a restart (exit code 129).
func Run(statusFile string) {
	initKlog()
	run(statusFile)
}

func initKlog() {
	var flags flag.FlagSet
	klog.InitFlags(&flags)
	if err := flags.Set("logtostderr", "true"); err != nil {
		logrus.WithError(err).Fatal("Failed to set klog logging configuration")
	}
}

func run(statusFile string) {
	logutils.ConfigureFormatter("kube-controllers")

	cfg := new(config.Config)
	if err := cfg.Parse(); err != nil {
		logrus.WithError(err).Fatal("Failed to parse config")
	}
	logrus.WithField("config", cfg).Info("Loaded configuration from environment")

	logLevel, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.WithError(err).Warnf("error parsing logLevel: %v", cfg.LogLevel)
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	k8sClientset, libcalicoClient, calicoClient, k8sconfig, err := getClients(cfg.Kubeconfig)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to start")
	}

	stop := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())

	s := status.New(statusFile)

	logrus.Info("Ensuring Calico datastore is initialized")
	s.SetReady("Startup", false, "initialized to false")
	initCtx, cancelInit := context.WithTimeout(ctx, 60*time.Second)
	for {
		err := libcalicoClient.EnsureInitialized(initCtx, "", "k8s")
		if err != nil {
			logrus.WithError(err).Info("Failed to initialize datastore")
			s.SetReady("Startup", false, fmt.Sprintf("Error initializing datastore: %v", err))
		} else {
			break
		}

		select {
		case <-initCtx.Done():
			logrus.Fatal("Failed to initialize Calico datastore")
		case <-time.After(5 * time.Second):
		}
	}
	logrus.Info("Calico datastore is initialized")
	s.SetReady("Startup", true, "")
	cancelInit()

	controllerCtrl := &controllerControl{
		ctx:         ctx,
		controllers: make(map[string]controller.Controller),
		stop:        stop,
		informers:   make([]cache.SharedIndexInformer, 0),
	}

	dataFeed := utils.NewDataFeed(libcalicoClient, cfg.DatastoreType)

	var runCfg config.RunConfig
	v, ok := os.LookupEnv(config.EnvEnabledControllers)
	if ok && strings.Contains(v, "flannelmigration") {
		if strings.Trim(v, " ,") != "flannelmigration" {
			logrus.WithField(config.EnvEnabledControllers, v).Fatal("flannelmigration must be the only controller running")
		}
		flannelConfig := new(flannelmigration.Config)
		if err := flannelConfig.Parse(); err != nil {
			logrus.WithError(err).Fatal("Failed to parse Flannel config")
		}
		logrus.WithField("flannelConfig", flannelConfig).Info("Loaded Flannel configuration from environment")

		flannelMigrationController := flannelmigration.NewFlannelMigrationController(ctx, k8sClientset, libcalicoClient, flannelConfig)
		controllerCtrl.controllers["FlannelMigration"] = flannelMigrationController

		runCfg.HealthEnabled = true
		runCfg.LogLevelScreen = logLevel

		controllerCtrl.restart = make(chan config.RunConfig)
	} else {
		logrus.Info("Getting initial config snapshot from datastore")
		cCtrlr := config.NewRunConfigController(ctx, *cfg, libcalicoClient.KubeControllersConfiguration())
		runCfg = <-cCtrlr.ConfigChan()
		logrus.Info("Got initial config snapshot")

		controllerCtrl.restart = cCtrlr.ConfigChan()
		controllerCtrl.initControllers(ctx, runCfg, k8sClientset, libcalicoClient, calicoClient, dataFeed, k8sconfig)
	}

	if cfg.DatastoreType == utils.Etcdv3 {
		go startCompactor(ctx, runCfg.EtcdV3CompactionPeriod)
	}

	if runCfg.HealthEnabled {
		logrus.Info("Starting status report routine")
		go runHealthChecks(ctx, s, k8sClientset, libcalicoClient)
	}

	logrus.SetLevel(runCfg.LogLevelScreen)

	if runCfg.PrometheusPort != 0 {
		logrus.Infof("Starting Prometheus metrics server on port %d", runCfg.PrometheusPort)
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(fmt.Sprintf(":%d", runCfg.PrometheusPort), mux); err != nil {
				logrus.WithError(err).Fatal("Failed to serve prometheus metrics")
			}
		}()
	}

	if runCfg.DebugProfilePort != 0 {
		debugserver.StartDebugPprofServer("0.0.0.0", int(runCfg.DebugProfilePort))
	}

	controllerCtrl.runControllers(dataFeed, runCfg)

	cancel()

	os.Exit(cmdwrapper.RestartReturnCode)
}

func runHealthChecks(ctx context.Context, s *status.Status, k8sClientset *kubernetes.Clientset, calicoClient client.Interface) {
	s.SetReady("CalicoDatastore", false, "initialized to false")
	s.SetReady("KubeAPIServer", false, "initialized to false")

	defaultTimeout := 4 * time.Second
	maxTimeout := 16 * time.Second
	timeout := defaultTimeout

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		healthCtx, cancel := context.WithTimeout(ctx, timeout)
		err := calicoClient.EnsureInitialized(healthCtx, "", "k8s")
		if err != nil {
			logrus.WithError(err).Errorf("Failed to verify datastore")
			s.SetReady("CalicoDatastore", false, fmt.Sprintf("Error verifying datastore: %v", err))
		} else {
			s.SetReady("CalicoDatastore", true, "")
		}
		cancel()

		healthCtx, cancel = context.WithTimeout(ctx, timeout)
		healthStatus := 0
		result := k8sClientset.Discovery().RESTClient().Get().AbsPath("/healthz").Do(healthCtx).StatusCode(&healthStatus)
		cancel()
		if healthStatus != http.StatusOK {
			logrus.WithError(result.Error()).WithField("status", healthStatus).Errorf("Received bad status code from apiserver")
			s.SetReady("KubeAPIServer", false, fmt.Sprintf("Error reaching apiserver: %v with http status code: %d", err, healthStatus))
		} else {
			s.SetReady("KubeAPIServer", true, "")
		}

		if !s.GetReadiness() {
			timeout = min(2*timeout, maxTimeout)
			logrus.Infof("Health check is not ready, retrying in 2 seconds with new timeout: %s", timeout)
			time.Sleep(2 * time.Second)
			continue
		}

		timeout = defaultTimeout
		time.Sleep(10 * time.Second)
	}
}

func startCompactor(ctx context.Context, interval time.Duration) {
	if interval.Nanoseconds() == 0 {
		logrus.Info("Disabling periodic etcdv3 compaction")
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		etcdClient, err := newEtcdV3Client()
		if err != nil {
			logrus.WithError(err).Error("Failed to start etcd compaction routine, retry in 1m")
			time.Sleep(1 * time.Minute)
			continue
		}

		logrus.WithField("period", interval).Info("Starting periodic etcdv3 compaction")
		etcd3.StartCompactorPerEndpoint(etcdClient, interval)
		break
	}
}

func getClients(kubeconfig string) (*kubernetes.Clientset, client.Interface, clientset.Interface, *rest.Config, error) {
	apiCfg, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	apiCfg.Spec.K8sClientQPS = 500

	libcalicoClient, err := client.New(*apiCfg)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to build Calico client: %w", err)
	}

	k8sconfig, err := winutils.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to build kubernetes client config: %w", err)
	}

	k8sconfig.QPS = 100
	k8sconfig.Burst = 200

	k8sClientset, err := kubernetes.NewForConfig(k8sconfig)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to build kubernetes client: %w", err)
	}

	var v3c clientset.Interface
	v3c, err = clientset.NewForConfig(k8sconfig)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to build Calico Kubernetes v3 client: %w", err)
	}

	return k8sClientset, libcalicoClient, v3c, k8sconfig, nil
}

func newEtcdV3Client() (*clientv3.Client, error) {
	apiCfg, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, err
	}

	if apiCfg.Spec.EtcdEndpoints != "" && apiCfg.Spec.EtcdDiscoverySrv != "" {
		logrus.Warning("Multiple etcd endpoint discovery methods specified in etcdv3 API config")
		return nil, fmt.Errorf("multiple discovery or bootstrap options specified, use either \"etcdEndpoints\" or \"etcdDiscoverySrv\"")
	}

	etcdLocation := []string{}
	if apiCfg.Spec.EtcdEndpoints != "" {
		etcdLocation = strings.Split(apiCfg.Spec.EtcdEndpoints, ",")
	}

	if apiCfg.Spec.EtcdDiscoverySrv != "" {
		srvs, srvErr := srv.GetClient("etcd-client", apiCfg.Spec.EtcdDiscoverySrv, "")
		if srvErr != nil {
			return nil, fmt.Errorf("failed to discover etcd endpoints through SRV discovery: %w", srvErr)
		}
		etcdLocation = srvs.Endpoints
	}

	if len(etcdLocation) == 0 {
		logrus.Warning("No etcd endpoints specified in etcdv3 API config")
		return nil, fmt.Errorf("no etcd endpoints specified")
	}

	tlsInfo := &transport.TLSInfo{
		TrustedCAFile: apiCfg.Spec.EtcdCACertFile,
		CertFile:      apiCfg.Spec.EtcdCertFile,
		KeyFile:       apiCfg.Spec.EtcdKeyFile,
	}
	tlsClient, err := tlsInfo.ClientConfig()
	if err != nil {
		return nil, err
	}

	baseTLSConfig, err := tls.NewTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS Config: %w", err)
	}
	tlsClient.MaxVersion = baseTLSConfig.MaxVersion
	tlsClient.MinVersion = baseTLSConfig.MinVersion
	tlsClient.CipherSuites = baseTLSConfig.CipherSuites
	tlsClient.CurvePreferences = baseTLSConfig.CurvePreferences
	tlsClient.Renegotiation = baseTLSConfig.Renegotiation

	etcdCfg := clientv3.Config{
		Endpoints:   etcdLocation,
		TLS:         tlsClient,
		DialTimeout: 10 * time.Second,
	}

	if apiCfg.Spec.EtcdUsername != "" && apiCfg.Spec.EtcdPassword != "" {
		etcdCfg.Username = apiCfg.Spec.EtcdUsername
		etcdCfg.Password = apiCfg.Spec.EtcdPassword
	}

	return clientv3.New(etcdCfg)
}

type controllerControl struct {
	ctx         context.Context
	controllers map[string]controller.Controller
	stop        chan struct{}
	restart     <-chan config.RunConfig
	informers   []cache.SharedIndexInformer
}

func (cc *controllerControl) initControllers(
	ctx context.Context,
	cfg config.RunConfig,
	k8sClientset *kubernetes.Clientset,
	calicoClient client.Interface,
	v3c clientset.Interface,
	dataFeed *utils.DataFeed,
	k8sconfig *rest.Config,
) {
	factory := informers.NewSharedInformerFactory(k8sClientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()
	nodeInformer := factory.Core().V1().Nodes().Informer()
	serviceInformer := factory.Core().V1().Services().Informer()
	namespaceInformer := factory.Core().V1().Namespaces().Informer()

	if v3c != nil {
		calicoFactory := externalversions.NewSharedInformerFactory(v3c, 5*time.Minute)
		poolInformer := calicoFactory.Projectcalico().V3().IPPools().Informer()
		blockInformer := calicoFactory.Projectcalico().V3().IPAMBlocks().Informer()

		apiCfg, _ := apiconfig.LoadClientConfigFromEnvironment()
		v3CRDs := k8s.UsingV3CRDs(&apiCfg.Spec)

		if v3CRDs {
			poolController := ippool.NewController(ctx, v3c, poolInformer, blockInformer, calicoClient.IPAM())
			cc.controllers["IPPool"] = poolController
			cc.registerInformers(poolInformer, blockInformer)

			tierInformer := calicoFactory.Projectcalico().V3().Tiers().Informer()
			gnpInformer := calicoFactory.Projectcalico().V3().GlobalNetworkPolicies().Informer()
			npInformer := calicoFactory.Projectcalico().V3().NetworkPolicies().Informer()
			sgnpInformer := calicoFactory.Projectcalico().V3().StagedGlobalNetworkPolicies().Informer()
			snpInformer := calicoFactory.Projectcalico().V3().StagedNetworkPolicies().Informer()
			tierController := tier.NewController(ctx, v3c, tierInformer, gnpInformer, npInformer, sgnpInformer, snpInformer)
			cc.controllers["Tier"] = tierController
			cc.registerInformers(tierInformer, gnpInformer, npInformer, sgnpInformer, snpInformer)
		}
	}

	if cfg.Controllers.WorkloadEndpoint != nil {
		podController := pod.NewPodController(ctx, k8sClientset, calicoClient, *cfg.Controllers.WorkloadEndpoint, podInformer)
		cc.controllers["Pod"] = podController
		cc.registerInformers(podInformer)
	}

	if cfg.Controllers.Namespace != nil {
		namespaceController := namespace.NewNamespaceController(ctx, k8sClientset, calicoClient, *cfg.Controllers.Namespace)
		cc.controllers["Namespace"] = namespaceController
	}
	if cfg.Controllers.Policy != nil {
		policyController := networkpolicy.NewPolicyController(ctx, k8sClientset, calicoClient, *cfg.Controllers.Policy)
		cc.controllers["NetworkPolicy"] = policyController
	}
	if cfg.Controllers.Node != nil {
		deferredInformers := kubevirt.NewDeferredInformers(kubevirt.NewIndexerFunc(k8sconfig, 5*time.Minute), 30*time.Second, cc.stop)
		nodeController := node.NewNodeController(ctx, k8sClientset, calicoClient, *cfg.Controllers.Node, nodeInformer, podInformer, dataFeed, deferredInformers)
		cc.controllers["Node"] = nodeController
		cc.registerInformers(podInformer, nodeInformer)
	}
	if cfg.Controllers.ServiceAccount != nil {
		serviceAccountController := serviceaccount.NewServiceAccountController(ctx, k8sClientset, calicoClient, *cfg.Controllers.ServiceAccount)
		cc.controllers["ServiceAccount"] = serviceAccountController
	}

	if cfg.Controllers.LoadBalancer != nil {
		loadBalancerController := loadbalancer.NewLoadBalancerController(k8sClientset, calicoClient, *cfg.Controllers.LoadBalancer, serviceInformer, namespaceInformer, dataFeed)
		cc.controllers["LoadBalancer"] = loadBalancerController
		cc.registerInformers(serviceInformer, namespaceInformer)
	}

	if cfg.Controllers.Migration != nil && cfg.Controllers.Migration.PolicyNameMigrator == "Enabled" {
		policyMigrator := networkpolicy.NewMigratorController(ctx, k8sClientset, calicoClient, dataFeed)
		cc.controllers["NetworkPolicyMigrator"] = policyMigrator
	}

	if err := podInformer.SetTransform(converter.PodTransformer(cfg.Controllers.WorkloadEndpoint != nil)); err != nil {
		logrus.WithError(err).Fatal("Failed to set transform on pod informer")
	}
}

func (cc *controllerControl) registerInformers(infs ...cache.SharedIndexInformer) {
	for _, inf := range infs {
		alreadyRegistered := false
		for _, registeredInf := range cc.informers {
			if inf == registeredInf {
				alreadyRegistered = true
			}
		}

		if !alreadyRegistered {
			cc.informers = append(cc.informers, inf)
		}
	}
}

func (cc *controllerControl) runControllers(dataFeed *utils.DataFeed, cfg config.RunConfig) {
	for _, inf := range cc.informers {
		logrus.WithField("informer", inf).Info("Starting informer")
		go inf.Run(cc.stop)
	}

	for controllerType, c := range cc.controllers {
		logrus.WithField("ControllerType", controllerType).Info("Starting controller")
		go c.Run(cc.stop)
	}

	dataFeed.Start()

	select {
	case <-cc.ctx.Done():
		logrus.Warn("context cancelled")
	case <-cc.restart:
		logrus.Warn("configuration changed; restarting")
	}
	close(cc.stop)
}
