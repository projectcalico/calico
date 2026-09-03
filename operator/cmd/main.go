// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/url"
	"os"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	clientgocache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/yaml"

	operatortigeraiov1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/internal/controller"
	"github.com/projectcalico/calico/operator/pkg/active"
	"github.com/projectcalico/calico/operator/pkg/admission"
	"github.com/projectcalico/calico/operator/pkg/apigroup"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/awssgsetup"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/common/discovery"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/metrics"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/crds"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
	operatortls "github.com/projectcalico/calico/operator/pkg/tls"
	"github.com/projectcalico/calico/operator/version"
	// +kubebuilder:scaffold:imports
)

var (
	defaultMetricsPort int32 = 9484
	scheme                   = runtime.NewScheme()
	setupLog                 = ctrl.Log.WithName("setup")
)

// bootstrapConfigMapName is the name of the ConfigMap that contains cluster-wide
// configuration for the operator loaded at startup.
const bootstrapConfigMapName = "operator-bootstrap-config"

func init() {
	// +kubebuilder:scaffold:scheme
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensions.AddToScheme(scheme))
	utilruntime.Must(operatortigeraiov1.AddToScheme(scheme))
}

func printVersion() {
	log.Info(fmt.Sprintf("Version: %v", version.VERSION))
	if version.BuildVariant != "" {
		log.Info(fmt.Sprintf("Variant: %s", version.BuildVariant))
	}
	log.Info(fmt.Sprintf("Go Version: %s", goruntime.Version()))
	log.Info(fmt.Sprintf("Go OS/Arch: %s/%s", goruntime.GOOS, goruntime.GOARCH))
}

func main() {
	var enableLeaderElection bool
	var leaderElectionLeaseDuration time.Duration
	var leaderElectionRenewDeadline time.Duration
	var leaderElectionRetryPeriod time.Duration
	// urlOnlyKubeconfig is a slight hack; we need to get the apiserver from the
	// kubeconfig but should use the in-cluster service account
	var urlOnlyKubeconfig string
	var showVersion bool
	var printImages string
	var printCalicoCRDs string
	var sgSetup bool
	var manageCRDs bool
	var preDelete bool
	var bootstrapVariant string

	// bootstrapCRDs is a flag that can be used to install the CRDs and exit. This is useful for
	// workflows that use an init container to install CustomResources prior to the operator starting.
	var bootstrapCRDs bool

	flag.BoolVar(
		&enableLeaderElection, "enable-leader-election", true,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.",
	)
	flag.DurationVar(
		&leaderElectionLeaseDuration, "leader-election-lease-duration", 15*time.Second,
		"Duration non-leader candidates wait before force-acquiring leadership.",
	)
	flag.DurationVar(
		&leaderElectionRenewDeadline, "leader-election-renew-deadline", 10*time.Second,
		"Duration the acting leader retries refreshing leadership before giving up.",
	)
	flag.DurationVar(
		&leaderElectionRetryPeriod, "leader-election-retry-period", 2*time.Second,
		"Duration the leader-election clients wait between action retries.",
	)
	flag.StringVar(
		&printCalicoCRDs, "print-calico-crds", "",
		`Print the Calico CRDs the operator has bundled then exit. Possible values: all, <crd prefix>.
If a value other than 'all' is specified, the first CRD with a prefix of the specified value will be printed.`,
	)
	flag.StringVar(&urlOnlyKubeconfig, "url-only-kubeconfig", "", "Path to a kubeconfig, but only for the apiserver url.")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.StringVar(&printImages, "print-images", "", "Print the default images the operator could deploy and exit. Possible values: list")
	flag.BoolVar(&sgSetup, "aws-sg-setup", false, "Setup Security Groups in AWS (should only be used on OpenShift).")
	flag.BoolVar(&manageCRDs, "manage-crds", false, "Operator should manage the projectcalico.org and operator.tigera.io CRDs.")
	flag.BoolVar(&preDelete, "pre-delete", false, "Run helm pre-deletion hook logic, then exit.")
	flag.BoolVar(&bootstrapCRDs, "bootstrap-crds", false, "Install CRDs and exit")
	flag.StringVar(
		&bootstrapVariant, "variant", string(operatortigeraiov1.Calico),
		`Product variant to install CRDs for before an Installation exists. Only affects CRD and
admission policy installation; once an Installation exists it is the authority on the variant.`,
	)

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.WriteTo(os.Stdout), zap.UseFlagOptions(&opts)))

	// An unrecognised variant is silently treated as Calico, which installs the wrong CRDs for
	// the bootstrap-crds path where nothing runs afterwards to correct them.
	switch v := operatortigeraiov1.ProductVariant(bootstrapVariant); {
	case v == operatortigeraiov1.Calico, v.IsEnterprise():
	default:
		fmt.Printf("Invalid -variant %q\n", bootstrapVariant)
		os.Exit(1)
	}

	if showVersion {
		// If the following line is updated then it might be necessary to update the assertOperatorImageVersion in hack/release/build.go
		fmt.Println("Operator:", version.VERSION)
		fmt.Println("Calico:", components.CalicoRelease)
		fmt.Println("Enterprise:", components.EnterpriseRelease)
		if version.BuildVariant != "" {
			fmt.Println("Variant:", version.BuildVariant)
		}
		os.Exit(0)
	}

	if printImages != "" {
		var cmpnts []components.Component
		if strings.ToLower(printImages) == "list" {
			cmpnts = components.CalicoImages
			cmpnts = append(cmpnts, components.EnterpriseImages...)
		} else if strings.ToLower(printImages) == "listcalico" {
			cmpnts = components.CalicoImages
		} else {
			fmt.Println("Invalid option for --print-images flag", printImages)
			os.Exit(1)
		}
		cmpnts = append(cmpnts, components.ComponentOperatorInit)
		for _, x := range cmpnts {
			ref, _ := components.GetReference(x, "", "", "", nil)
			fmt.Println(ref)
		}
		os.Exit(0)
	}

	if printCalicoCRDs != "" {
		if err := showCRDs(operatortigeraiov1.Calico, printCalicoCRDs); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if urlOnlyKubeconfig != "" {
		if err := setKubernetesServiceEnv(urlOnlyKubeconfig); err != nil {
			setupLog.Error(err, "Terminating")
			os.Exit(1)
		}
	}

	printVersion()

	ctx, cancel := context.WithCancel(context.Background())

	cfg, err := config.GetConfig()
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	v3CRDs, err := apis.UseV3CRDS(cfg)
	if err != nil {
		log.Error(err, "Failed to determine CRD version to use")
		os.Exit(1)
	}

	// Tell the component handler which API group to inject into workloads.
	if v3CRDs {
		apigroup.Set(apigroup.V3)
	}

	// Add the Calico API to the scheme, now that we know which backing CRD version to use.
	utilruntime.Must(apis.AddToScheme(scheme, v3CRDs))

	// Because we only run this as a job that is set up by the operator, it should not be
	// launched except by an operator that is the active operator. So we do not need to
	// check that we're the active operator before running the AWS SG setup.
	if sgSetup {
		log.Info("Setting up AWS Security Groups")

		err = awssgsetup.SetupAWSSecurityGroups(ctx, c, os.Getenv("HOSTED_OPENSHIFT") == "true")
		if err != nil {
			log.Error(err, "")
			os.Exit(1)
		}
		os.Exit(0)
	}

	if preDelete {
		// We've built a client - we can use it to clean up.
		if err := executePreDeleteHook(ctx, c); err != nil {
			log.Error(err, "Failed to complete pre-delete hook")
			os.Exit(1)
		}
		os.Exit(0)
	}

	// sigHandler is a context that is canceled when we receive a termination
	// signal. We don't want to immeditely terminate upon receipt of such a signal since
	// there may be cleanup required. So, we will pass a separate context to our controllers.
	// That context will be canceled after a successful cleanup.
	sigHandler := ctrl.SetupSignalHandler()
	active.WaitUntilActive(cs, c, sigHandler, setupLog)
	log.Info("Active operator: proceeding")

	metricsOpts := server.Options{
		BindAddress: metricsAddr(),
	}
	if common.MetricsTLSEnabled() {
		metricsOpts.SecureServing = true
		clientAuth, err := operatortls.ParseClientAuthType(os.Getenv("METRICS_CLIENT_AUTH"))
		if err != nil {
			setupLog.Error(err, "invalid METRICS_CLIENT_AUTH")
			os.Exit(1)
		}
		minVersion, err := operatortls.ParseTLSVersion(os.Getenv("TLS_MIN_VERSION"))
		if err != nil {
			setupLog.Error(err, "invalid TLS_MIN_VERSION")
			os.Exit(1)
		}
		getCert := getCertificateFromFile(metricsTLSCertFile(), metricsTLSKeyFile())
		metricsOpts.TLSOpts = []func(*tls.Config){
			func(cfg *tls.Config) {
				cfg.GetCertificate = getCert
				cfg.ClientAuth = clientAuth
				cfg.MinVersion = minVersion
				// Re-read ClientCAs per connection so kubelet volume updates and CA
				// rotations are picked up without an operator restart. The CA Secret
				// is created by the operator after pod start, so an eager one-shot
				// load would leave the trust pool permanently empty.
				cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
					pool, err := loadClientCAFromFile(metricsTLSCAFile())
					if err != nil {
						return nil, err
					}
					c := cfg.Clone()
					c.ClientAuth = clientAuth
					c.ClientCAs = pool
					return c, nil
				}
			},
		}
	}

	mgrOpts := ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsOpts,
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		LeaderElection:   enableLeaderElection,
		LeaderElectionID: "operator-lock",
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{
					// Pods are only listed by label/namespace selector from a handful of
					// controllers. Caching them starts a shared informer that holds every pod
					// in the cluster in memory (~36 MiB per 1000 pods), so read them uncached
					// from the apiserver instead.
					&corev1.Pod{},
				},
			},
		},

		// Cached objects are only read by the operator's own controllers, which
		// never consult managedFields; stripping them substantially shrinks the cache.
		Cache: cache.Options{DefaultTransform: cache.TransformStripManagedFields()},

		// Explicitly set the MapperProvider to the NewDynamicRESTMapper, as we had previously had issues with the default
		// not being this mapper (which has since been rectified). It was a tough issue to figure out when the default
		// had changed out from under us, so better to continue to explicitly set it as we know this is the mapper we want.
		MapperProvider: apiutil.NewDynamicRESTMapper,

		LeaseDuration: &leaderElectionLeaseDuration,
		RenewDeadline: &leaderElectionRenewDeadline,
		RetryPeriod:   &leaderElectionRetryPeriod,
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOpts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Snapshot the served versions for the Kubernetes APIs the operator branches on. Discovery
	// happens once here so reconcile loops can do plain map lookups.
	apiDiscovery := discovery.DiscoverAPIs(mgr.GetRESTMapper())

	// If configured to manage CRDs, do a preliminary install of them here. The Installation controller
	// will reconcile them as well, but we need to make sure they are installed before we start the rest of the controllers.
	if bootstrapCRDs || manageCRDs {
		setupLog.WithValues("v3", v3CRDs).Info("Ensuring CRDs are installed")

		if err := crds.Ensure(mgr.GetClient(), bootstrapVariant, v3CRDs, setupLog); err != nil {
			setupLog.Error(err, "Failed to ensure CRDs are created")
			os.Exit(1)
		}

		if err := admission.Ensure(mgr.GetClient(), bootstrapVariant, v3CRDs, apiDiscovery.ServedVersion(admission.APIGroup, admission.KindPolicy), setupLog); err != nil {
			setupLog.Error(err, "Failed to ensure MutatingAdmissionPolicies are created")
			os.Exit(1)
		}

		if err := admission.EnsureValidating(mgr.GetClient(), bootstrapVariant, v3CRDs, apiDiscovery.ServedVersion(admission.APIGroup, admission.KindValidatingPolicy), setupLog); err != nil {
			setupLog.Error(err, "Failed to ensure ValidatingAdmissionPolicies are created")
			os.Exit(1)
		}

		if bootstrapCRDs {
			setupLog.Info("CRDs installed successfully")
			os.Exit(0)
		}
	}

	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to get Kubernetes clientset")
		os.Exit(1)
	}

	// Attempt to auto discover the provider
	provider, err := discovery.AutoDiscoverProvider(ctx, clientset)
	if err != nil {
		setupLog.Error(err, "Auto discovery of Provider failed")
		os.Exit(1)
	}
	setupLog.WithValues("provider", provider).Info("Checking type of cluster")

	clusterDomain, err := dns.GetClusterDomain(dns.DefaultResolveConfPath)
	if err != nil {
		clusterDomain = dns.DefaultClusterDomain
		log.Error(err, fmt.Sprintf("Couldn't find the cluster domain from the resolv.conf, defaulting to %s", clusterDomain))
	}

	kubernetesVersion, err := common.GetKubernetesVersion(clientset)
	if err != nil {
		log.Error(err, "Unable to resolve Kubernetes version, defaulting to v1.18")
		kubernetesVersion = &common.VersionInfo{Major: 1, Minor: 18}
	}

	// Resolve the variant now that the operator CRDs exist.
	variant := waitForVariant(ctx, c, setupLog)
	setupLog.WithValues("variant", variant).Info("Resolved product variant")

	// The bootstrap pass above used the flag default, which doesn't cover the enterprise APIs.
	if manageCRDs && variant != operatortigeraiov1.ProductVariant(bootstrapVariant) {
		setupLog.WithValues("variant", variant).Info("Ensuring CRDs are installed for the resolved variant")

		if err := crds.Ensure(mgr.GetClient(), string(variant), v3CRDs, setupLog); err != nil {
			setupLog.Error(err, "Failed to ensure CRDs are created")
			os.Exit(1)
		}
	}

	extensionRegistry, err := extensions.Build(ctx, variant, clientset, extensions.BuildOptions{ManageCRDs: manageCRDs, UseV3CRDs: v3CRDs})
	if err != nil {
		setupLog.Error(err, "Failed to build the variant's extensions")
		os.Exit(1)
	}
	setupLog.WithValues("tenancy", extensionRegistry.Startup().MultiTenant()).Info("Checking tenancy mode")

	// The variant's controllers can't register without their APIs. Exiting lets the kubelet
	// retry us once the CRDs are installed.
	if err := extensionRegistry.Startup().VerifyAPIsExist(cs); err != nil {
		setupLog.Error(err, "Cannot run as the configured variant")
		os.Exit(1)
	}

	// Start a goroutine to handle termination.
	go func() {
		// Cancel the main context when we are done.
		defer cancel()

		// Wait for a signal.
		<-sigHandler.Done()

		// Check if we need to do any cleanup.
		client := mgr.GetClient()
		instance := &operatortigeraiov1.Installation{}
		retries := 0
		for {
			if err := client.Get(ctx, utils.DefaultInstanceKey, instance); errors.IsNotFound(err) {
				// No installation - we can exit immediately.
				return
			} else if err != nil {
				// Error querying - retry after a small sleep.
				if retries >= 5 {
					log.Errorf("Too many retries, exiting with error: %s", err)
					return
				}
				log.Errorf("Error querying Installation, will retry: %s", err)
				retries++
				time.Sleep(1 * time.Second)
				continue
			}

			// Success
			break
		}

		if instance.DeletionTimestamp == nil {
			// Installation isn't terminating, so we can exit immediately.
			return
		}

		// We need to wait for termination to complete. We can do this by checking if the Installation
		// resource has been cleaned up or not.
		to := 60 * time.Second
		log.Infof("Waiting up to %s for graceful termination to complete", to)
		timeout := time.After(to)
		for {
			select {
			case <-timeout:
				// Timeout. Continue with shutdown.
				log.Warning("Timed out waiting for graceful shutdown to complete")
				return
			default:
				err := client.Get(ctx, utils.DefaultInstanceKey, instance)
				if errors.IsNotFound(err) {
					// Installation has been cleaned up, we can terminate.
					log.Info("Graceful termination complete")
					return
				} else if err != nil {
					log.Errorf("Error querying Installation: %s", err)
				}
				time.Sleep(1 * time.Second)
			}
		}
	}()

	// The operator MUST not run within one of the Namespaces that it itself manages. Perform an early check here
	// to make sure that we're not doing so, and exit if we are.
	// Components share namespaces, so dedupe before the error lists them.
	badNamespaces := sets.New(common.CalicoNamespace, render.CSIDaemonSetNamespace).
		Insert(extensionRegistry.Startup().ProtectedNamespaces()...).
		UnsortedList()
	for _, ns := range badNamespaces {
		if common.OperatorNamespace() == ns {
			log.Error("Operator must not be run within a Namespace managed by the operator, please select a different namespace")
			log.Error(fmt.Sprintf("The following namespaces cannot be used: %s", badNamespaces))
			os.Exit(1)
		}
	}

	// Load the operator's bootstrap ConfigMap, if it exists.
	bootConfig, err := clientset.CoreV1().ConfigMaps(common.OperatorNamespace()).Get(ctx, bootstrapConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "Failed to load bootstrap configmap")
			os.Exit(1)
		}
	}

	elasticIsMigrating := false
	useSingleIndex := false
	useExternalElastic := discovery.UseExternalElastic(bootConfig)

	if extensionRegistry.Startup().Cloud() {
		elasticIsMigrating = discovery.ElasticIsMigrating(bootConfig)
		useSingleIndex = discovery.UseSingleIndex(bootConfig)
		if err := extensionRegistry.Startup().VerifyClusterState(ctx, cs, elasticIsMigrating, useExternalElastic); err != nil {
			setupLog.Error(err, "Cluster state verification failed")
			os.Exit(1)
		}
	}

	// Start a watch on our bootstrap configmap so we can restart if it changes.
	if err = utils.MonitorConfigMap(ctx, mgr.GetCache(), bootstrapConfigMapName, bootConfig.Data); err != nil {
		log.Error(err, "Failed to monitor bootstrap configmap")
		os.Exit(1)
	}

	// Same for the variant, which the process can only change by restarting.
	if err = monitorVariant(ctx, mgr, variant); err != nil {
		log.Error(err, "Failed to monitor the product variant")
		os.Exit(1)
	}

	options := options.ControllerOptions{
		DetectedProvider:  provider,
		Variant:           variant,
		ClusterDomain:     clusterDomain,
		KubernetesVersion: kubernetesVersion,
		ManageCRDs:        manageCRDs,
		ShutdownContext:   ctx,
		K8sClientset:      clientset,
		MultiTenant:       extensionRegistry.Startup().MultiTenant(),
		ElasticExternal:   useExternalElastic,
		Cloud:             extensionRegistry.Startup().Cloud(),
		ESMigration:       elasticIsMigrating,
		UseSingleIndex:    useSingleIndex,
		UseV3CRDs:         v3CRDs,
		APIDiscovery:      apiDiscovery,
		Extensions:        extensionRegistry,
	}

	err = controller.AddToManager(mgr, options)
	if err != nil {
		setupLog.Error(err, "unable to create controllers")
		os.Exit(1)
	}

	// Register custom Prometheus metrics collector.
	if common.MetricsEnabled() {
		collector := metrics.NewOperatorCollector(mgr.GetClient())
		ctrlmetrics.Registry.MustRegister(collector)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// setKubernetesServiceEnv configured the environment with the location of the Kubernetes API
// based on the provided kubeconfig file. We need this since we can't rely on the kube-proxy being present,
// since this operator may be the one installing the proxy! It's based off of logic in the cluster-network-operator.
// https://github.com/openshift/cluster-network-operator/blob/4d8a780f7b0f8b6a258aaba002a77d3313fa8fc8/cmd/cluster-network-operator/main.go#L32-L72
func setKubernetesServiceEnv(kubeconfigFile string) error {
	kubeconfig, err := clientcmd.LoadFromFile(kubeconfigFile)
	if err != nil {
		return err
	}
	clusterName := kubeconfig.Contexts[kubeconfig.CurrentContext].Cluster
	apiURL := kubeconfig.Clusters[clusterName].Server

	url, err := url.Parse(apiURL)
	if err != nil {
		return err
	}

	// The kubernetes in-cluster functions don't let you override the apiserver
	// directly; gotta "pass" it via environment vars.
	log.Info("Overriding kubernetes api to %s", apiURL)
	err = os.Setenv("KUBERNETES_SERVICE_HOST", url.Hostname())
	if err != nil {
		return err
	}
	err = os.Setenv("KUBERNETES_SERVICE_PORT", url.Port())
	if err != nil {
		return err
	}
	return nil
}

// waitForVariant blocks until an Installation exists and returns the variant it asks for. The
// operator has nothing to do before then, and the bootstrap flag is only ever for the CRDs above.
func waitForVariant(ctx context.Context, c client.Client, log logr.Logger) operatortigeraiov1.ProductVariant {
	for first := true; ; first = false {
		variant, err := effectiveVariant(ctx, c)
		switch {
		case err != nil:
			log.Error(err, "Failed to read the Installation, will retry")
		case variant != "":
			return variant
		case first:
			log.Info("Waiting for an Installation")
		}

		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			log.Info("Requested to stop while waiting for an Installation")
			os.Exit(0)
		}
	}
}

// effectiveVariant returns the variant the Installation asks for, merging in the overlay. It
// returns an empty variant when no Installation exists.
func effectiveVariant(ctx context.Context, c client.Client) (operatortigeraiov1.ProductVariant, error) {
	instance := &operatortigeraiov1.Installation{}
	if err := c.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if errors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	spec := instance.Spec

	// The overlay can set the variant like any other field, so it has to be merged in.
	overlay := &operatortigeraiov1.Installation{}
	if err := c.Get(ctx, utils.OverlayInstanceKey, overlay); err != nil {
		if !errors.IsNotFound(err) {
			return "", err
		}
	} else {
		spec = utils.OverrideInstallationSpec(spec, overlay.Spec)
	}

	if spec.Variant == "" {
		// An Installation that doesn't ask for a variant gets Calico.
		return operatortigeraiov1.Calico, nil
	}
	return spec.Variant, nil
}

// monitorVariant restarts the operator when the effective variant moves off the one this
// process booted with.
func monitorVariant(ctx context.Context, mgr manager.Manager, booted operatortigeraiov1.ProductVariant) error {
	// The cache isn't running yet, so don't wait on a sync that can't happen.
	informer, err := mgr.GetCache().GetInformer(ctx, &operatortigeraiov1.Installation{}, cache.BlockUntilSynced(false))
	if err != nil {
		return err
	}

	// Re-resolve rather than reading the event's object, since the effective variant is the
	// merge of the default Installation and the overlay.
	c := mgr.GetClient()
	check := func() {
		// Exiting mid-uninstall would skip the graceful termination wait in main, which
		// holds the process open so controllers can run their finalizers.
		instance := &operatortigeraiov1.Installation{}
		if err := c.Get(ctx, utils.DefaultInstanceKey, instance); err == nil && instance.DeletionTimestamp != nil {
			return
		}

		requested, err := effectiveVariant(ctx, c)
		if err != nil {
			log.Error(err, "Failed to resolve the requested variant")
			return
		}

		if requested != "" && requested != booted {
			log.Info("Requested variant changed, rebooting", "booted", booted, "requested", requested)
			os.Exit(0)
		}
	}

	_, err = informer.AddEventHandler(clientgocache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { check() },
		UpdateFunc: func(_, _ any) { check() },
		DeleteFunc: func(any) { check() },
	})
	return err
}

func showCRDs(variant operatortigeraiov1.ProductVariant, outputType string) error {
	first := true
	for _, v := range crds.GetCRDs(variant, os.Getenv("CALICO_API_GROUP") == "projectcalico.org/v3") {
		if outputType != "all" {
			if !strings.HasPrefix(v.Name, outputType) {
				continue
			}
		}
		b, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to Marshal %s: %v", v.Name, err)
		}
		if !first {
			fmt.Println("---")
		}
		first = false

		fmt.Printf("# %s\n", v.Name)
		fmt.Println(string(b))
	}
	// Indicates nothing was printed so we couldn't find the requested outputType
	if first {
		return fmt.Errorf("no CRD matching %s", outputType)
	}

	return nil
}

func executePreDeleteHook(ctx context.Context, c client.Client) error {
	defer log.Info("preDelete hook exiting")

	// Clean up any custom-resources first - this will trigger teardown of pods deloyed
	// by the operator, and give the operator a chance to clean up gracefully.
	installation := &operatortigeraiov1.Installation{}
	installation.Name = utils.DefaultInstanceKey.Name
	apiserver := &operatortigeraiov1.APIServer{}
	apiserver.Name = utils.DefaultInstanceKey.Name
	whisker := &operatortigeraiov1.Whisker{}
	whisker.Name = utils.DefaultInstanceKey.Name
	goldmane := &operatortigeraiov1.Goldmane{}
	goldmane.Name = utils.DefaultInstanceKey.Name
	for _, o := range []client.Object{whisker, goldmane, installation, apiserver} {
		if err := c.Delete(ctx, o); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return err
		}
	}

	// Wait for the Installation to be deleted.
	to := time.After(5 * time.Minute)
	for {
		select {
		case <-to:
			return fmt.Errorf("timeout waiting for pre-delete hook")
		default:
			if err := c.Get(ctx, utils.DefaultInstanceKey, installation); errors.IsNotFound(err) {
				// It's gone! We can return.
				return nil
			}
		}
		log.Info("Waiting for Installation to be fully deleted")
		time.Sleep(5 * time.Second)
	}
}
