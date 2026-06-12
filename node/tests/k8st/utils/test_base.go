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

// test_base.go is the Go port of node/tests/k8st/test_base.py: the
// workload/service fixtures shared across the k8st suites. Kubernetes-native
// objects (Namespace, Deployment, Service, Pod, node labels) go through
// client-go; Calico v3 CRDs go through calicoctl or a v3 controller-runtime
// client in the individual test files; docker-side helpers (external BGP
// routers, curl from outside the cluster) shell out to docker.
package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/ptr"
)

// NginxImage is the web-server image deployed behind the BGP-advertised
// services. Overridable via $NGINX_IMAGE to mirror utils.py.
var NginxImage = envOr("NGINX_IMAGE", "nginx:1")

// ----------------------------------------------------------------------------
// IDs.

// GenerateUniqueID returns "<prefix>-<random>" with a random suffix of the
// requested length drawn from [a-z0-9]. Mirrors utils.py:generate_unique_id.
func GenerateUniqueID(t testing.TB, length int, prefix string) string {
	t.Helper()
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generating random id: %v", err)
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return fmt.Sprintf("%s-%s", prefix, string(buf))
}

// ----------------------------------------------------------------------------
// Namespaces.

// CreateNamespace creates a namespace. Mirrors test_base.py:create_namespace.
func CreateNamespace(t testing.TB, name string) {
	t.Helper()
	cs := K8sClient(t)
	_, err := cs.CoreV1().Namespaces().Create(context.Background(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating namespace %s: %v", name, err)
	}
}

// DeleteNamespaceAndConfirm deletes a namespace and blocks until the API no
// longer returns it. Mirrors test_base.py:delete_and_confirm(ns, "ns").
func DeleteNamespaceAndConfirm(t testing.TB, name string) {
	t.Helper()
	cs := K8sClient(t)
	err := cs.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Logf("deleting namespace %s: %v", name, err)
	}
	err = RetryUntilSuccess(t, 120*time.Second, func() error {
		_, err := cs.CoreV1().Namespaces().Get(context.Background(), name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("namespace %s still exists", name)
	})
	if err != nil {
		t.Fatalf("namespace %s was not deleted: %v", name, err)
	}
}

// ----------------------------------------------------------------------------
// Deployments and services.

// DeployOptions controls Deploy. Zero values default to a single-replica
// NodePort service with externalTrafficPolicy=Local, matching test_base.py.
type DeployOptions struct {
	Image         string
	Name          string
	Namespace     string
	Port          int32
	Replicas      int32
	SvcType       corev1.ServiceType
	TrafficPolicy corev1.ServiceExternalTrafficPolicyType
	ClusterIP     string
	ExternalIP    string
	IPv6          bool
}

// Deploy creates a Deployment with a pod anti-affinity (so the scheduler
// spreads replicas across nodes) plus a matching Service. Mirrors
// test_base.py:deploy.
func Deploy(t testing.TB, opts DeployOptions) {
	t.Helper()
	cs := K8sClient(t)

	replicas := opts.Replicas
	if replicas == 0 {
		replicas = 1
	}
	selector := map[string]string{"app": opts.Name}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: opts.Name},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: selector},
				Spec: corev1.PodSpec{
					// Prefer spreading replicas onto different nodes so tests
					// that expect cross-node placement are reliable.
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
								Weight: 100,
								PodAffinityTerm: corev1.PodAffinityTerm{
									LabelSelector: &metav1.LabelSelector{MatchLabels: selector},
									TopologyKey:   "kubernetes.io/hostname",
								},
							}},
						},
					},
					Containers: []corev1.Container{{
						Name:  opts.Name,
						Image: opts.Image,
						Ports: []corev1.ContainerPort{{ContainerPort: opts.Port}},
					}},
				},
			},
		},
	}
	if _, err := cs.AppsV1().Deployments(opts.Namespace).Create(context.Background(), deployment, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating deployment %s/%s: %v", opts.Namespace, opts.Name, err)
	}

	CreateService(t, ServiceOptions{
		Name:          opts.Name,
		App:           opts.Name,
		Namespace:     opts.Namespace,
		Port:          opts.Port,
		Type:          opts.SvcType,
		TrafficPolicy: opts.TrafficPolicy,
		ClusterIP:     opts.ClusterIP,
		ExternalIP:    opts.ExternalIP,
		IPv6:          opts.IPv6,
	})
}

// ServiceOptions controls CreateService. Zero values default to a NodePort
// service with externalTrafficPolicy=Local, matching test_base.py.
type ServiceOptions struct {
	Name          string
	App           string
	Namespace     string
	Port          int32
	Type          corev1.ServiceType
	TrafficPolicy corev1.ServiceExternalTrafficPolicyType
	ClusterIP     string
	ExternalIP    string
	IPv6          bool
}

// CreateService creates a Service selecting pods labelled app=<App>. Mirrors
// test_base.py:create_service.
func CreateService(t testing.TB, opts ServiceOptions) {
	t.Helper()
	cs := K8sClient(t)

	svcType := opts.Type
	if svcType == "" {
		svcType = corev1.ServiceTypeNodePort
	}
	trafficPolicy := opts.TrafficPolicy
	if trafficPolicy == "" {
		trafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   opts.Name,
			Labels: map[string]string{"name": opts.Name},
		},
		Spec: corev1.ServiceSpec{
			Ports:                 []corev1.ServicePort{{Port: opts.Port}},
			Selector:              map[string]string{"app": opts.App},
			Type:                  svcType,
			ExternalTrafficPolicy: trafficPolicy,
		},
	}
	if svcType == corev1.ServiceTypeLoadBalancer {
		// Pin LB IPAM to Calico's loadbalancer controller. Without this,
		// metallb's ServiceReconciler (still installed for Gateway API
		// conformance L2 reachability) treats the unclassified Service as its
		// own and races Calico's status updates with empty-status writes.
		svc.Spec.LoadBalancerClass = ptr.To("calico")
	}
	if opts.ClusterIP != "" {
		svc.Spec.ClusterIP = opts.ClusterIP
	}
	if opts.ExternalIP != "" {
		svc.Spec.ExternalIPs = []string{opts.ExternalIP}
	}
	if opts.IPv6 {
		svc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv6Protocol}
	}

	if _, err := cs.CoreV1().Services(opts.Namespace).Create(context.Background(), svc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating service %s/%s: %v", opts.Namespace, opts.Name, err)
	}
}

// WaitUntilServiceExists blocks until the named Service is queryable, fatally
// failing the test on timeout. Mirrors test_base.py:wait_until_exists for the
// "svc" resource type (the only type the callers use).
func WaitUntilServiceExists(t testing.TB, name, namespace string) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 90*time.Second, func() error {
		_, err := cs.CoreV1().Services(namespace).Get(context.Background(), name, metav1.GetOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("service %s/%s never appeared: %v", namespace, name, err)
	}
}

// WaitForDeployment blocks until the Deployment has rolled out all of its
// replicas, fatally failing the test on timeout. The client-go equivalent of
// `kubectl rollout status deployment/<name>`. Mirrors
// test_base.py:wait_for_deployment.
func WaitForDeployment(t testing.TB, name, namespace string) {
	t.Helper()
	cs := K8sClient(t)
	t.Logf("Checking status for deployment %s/%s", namespace, name)
	err := RetryUntilSuccess(t, 120*time.Second, func() error {
		d, err := cs.AppsV1().Deployments(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		if d.Status.ObservedGeneration < d.Generation {
			return fmt.Errorf("deployment %s/%s not yet observed (gen %d < %d)",
				namespace, name, d.Status.ObservedGeneration, d.Generation)
		}
		if d.Status.UpdatedReplicas != want || d.Status.AvailableReplicas != want {
			return fmt.Errorf("deployment %s/%s rollout incomplete: updated=%d available=%d want=%d",
				namespace, name, d.Status.UpdatedReplicas, d.Status.AvailableReplicas, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("deployment %s/%s did not roll out: %v", namespace, name, err)
	}
}

// ScaleDeployment sets the Deployment's replica count. Mirrors
// test_base.py:scale_deployment.
func ScaleDeployment(t testing.TB, name, namespace string, replicas int32) {
	t.Helper()
	cs := K8sClient(t)
	scale, err := cs.AppsV1().Deployments(namespace).GetScale(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting scale for deployment %s/%s: %v", namespace, name, err)
	}
	scale.Spec.Replicas = replicas
	if _, err := cs.AppsV1().Deployments(namespace).UpdateScale(context.Background(), name, scale, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("scaling deployment %s/%s to %d: %v", namespace, name, replicas, err)
	}
}

// DeleteServiceAndConfirm deletes a Service and blocks until the API no longer
// returns it. Mirrors test_base.py:delete_and_confirm(svc, "svc").
func DeleteServiceAndConfirm(t testing.TB, name, namespace string) {
	t.Helper()
	cs := K8sClient(t)
	err := cs.CoreV1().Services(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Logf("deleting service %s/%s: %v", namespace, name, err)
	}
	err = RetryUntilSuccess(t, 120*time.Second, func() error {
		_, err := cs.CoreV1().Services(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("service %s/%s still exists", namespace, name)
	})
	if err != nil {
		t.Fatalf("service %s/%s was not deleted: %v", namespace, name, err)
	}
}

// AddServiceExternalIPs sets spec.externalIPs on a Service. Mirrors
// test_base/_TestBGPAdvert.add_svc_external_ips.
func AddServiceExternalIPs(t testing.TB, name, namespace string, ips []string) {
	t.Helper()
	cs := K8sClient(t)
	svc, err := cs.CoreV1().Services(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting service %s/%s: %v", namespace, name, err)
	}
	svc.Spec.ExternalIPs = ips
	if _, err := cs.CoreV1().Services(namespace).Update(context.Background(), svc, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("adding external IPs to service %s/%s: %v", namespace, name, err)
	}
}

// ServiceClusterIP returns the Service's clusterIP. Mirrors
// _TestBGPAdvert.get_svc_cluster_ip.
func ServiceClusterIP(t testing.TB, name, namespace string) string {
	t.Helper()
	svc, err := K8sClient(t).CoreV1().Services(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting service %s/%s: %v", namespace, name, err)
	}
	return svc.Spec.ClusterIP
}

// ServiceLoadBalancerIP waits up to ~10s for and returns the Service's
// allocated LoadBalancer ingress IP. Mirrors
// _TestBGPAdvert.get_svc_loadbalancer_ip.
func ServiceLoadBalancerIP(t testing.TB, name, namespace string) string {
	t.Helper()
	cs := K8sClient(t)
	var ip string
	err := RetryUntilSuccess(t, 15*time.Second, func() error {
		svc, err := cs.CoreV1().Services(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		ingress := svc.Status.LoadBalancer.Ingress
		if len(ingress) == 0 || ingress[0].IP == "" {
			return fmt.Errorf("no LoadBalancer IP for service %s/%s yet", namespace, name)
		}
		ip = ingress[0].IP
		return nil
	})
	if err != nil {
		t.Fatalf("no LoadBalancer IP found for service %s/%s: %v", namespace, name, err)
	}
	return ip
}

// ServiceHostIP returns the host IP of the first pod backing the given app.
// Mirrors _TestBGPAdvert.get_svc_host_ip.
func ServiceHostIP(t testing.TB, app, namespace string) string {
	t.Helper()
	cs := K8sClient(t)
	pods, err := cs.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=" + app,
	})
	if err != nil {
		t.Fatalf("listing pods app=%s in %s: %v", app, namespace, err)
	}
	if len(pods.Items) == 0 {
		t.Fatalf("no pods found for app=%s in %s", app, namespace)
	}
	return pods.Items[0].Status.HostIP
}

// ----------------------------------------------------------------------------
// Node labels.

// SetNodeLabel sets (or overwrites) a label on a Kubernetes Node. Mirrors
// `kubectl label node <node> key=value --overwrite`.
func SetNodeLabel(t testing.TB, node, key, value string) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 30*time.Second, func() error {
		n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		n.Labels[key] = value
		_, err = cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("labelling node %s %s=%s: %v", node, key, value, err)
	}
}

// RemoveNodeLabel removes a label from a Kubernetes Node. Mirrors
// `kubectl label node <node> key-`.
func RemoveNodeLabel(t testing.TB, node, key string) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 30*time.Second, func() error {
		n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if _, ok := n.Labels[key]; !ok {
			return nil
		}
		delete(n.Labels, key)
		_, err = cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("removing label %s from node %s: %v", key, node, err)
	}
}

// SetNodeAnnotation sets (or overwrites) an annotation on a Kubernetes Node.
// Mirrors `kubectl annotate node <node> key=value`.
func SetNodeAnnotation(t testing.TB, node, key, value string) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 30*time.Second, func() error {
		n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if n.Annotations == nil {
			n.Annotations = map[string]string{}
		}
		n.Annotations[key] = value
		_, err = cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("annotating node %s %s=%s: %v", node, key, value, err)
	}
}

// RemoveNodeAnnotation removes an annotation from a Kubernetes Node. Mirrors
// `kubectl annotate node <node> key-`.
func RemoveNodeAnnotation(t testing.TB, node, key string) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, 30*time.Second, func() error {
		n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if _, ok := n.Annotations[key]; !ok {
			return nil
		}
		delete(n.Annotations, key)
		_, err = cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Fatalf("removing annotation %s from node %s: %v", key, node, err)
	}
}

// ----------------------------------------------------------------------------
// External docker containers (BGP routers, etc.).

// Container wraps a detached docker container on the kind network. Mirrors
// test_base.py:Container.
type Container struct {
	t  testing.TB
	ID string
	ip string
}

// NewContainer runs `docker run --rm -d --net=kind <flags> <image> <args>` and
// returns a handle to the started container.
func NewContainer(t testing.TB, image, args, flags string) *Container {
	t.Helper()
	out := MustRun(t, fmt.Sprintf("docker run --rm -d --net=kind %s %s %s", flags, image, args))
	lines := strings.Split(strings.TrimSpace(out), "\n")
	id := strings.TrimSpace(lines[len(lines)-1])
	return &Container{t: t, ID: id}
}

// Kill force-removes the container.
func (c *Container) Kill() {
	c.t.Helper()
	_, _ = Run(c.t, "docker rm -f "+c.ID, RunOptions{AllowFail: true})
}

// Inspect runs `docker inspect -f <template>` against the container.
func (c *Container) Inspect(template string) string {
	c.t.Helper()
	return MustRun(c.t, fmt.Sprintf("docker inspect -f '%s' %s", template, c.ID))
}

// IP returns (and caches) the container's IP on the kind network.
func (c *Container) IP() string {
	c.t.Helper()
	if c.ip == "" {
		c.ip = strings.TrimSpace(c.Inspect("{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"))
	}
	return c.ip
}

// Execute runs a command inside the container via `docker exec`.
func (c *Container) Execute(cmd string) string {
	c.t.Helper()
	return MustRun(c.t, fmt.Sprintf("docker exec %s %s", c.ID, cmd))
}

// StartExternalNodeWithBGP starts a privileged BIRD container on the kind
// network and configures its BGP peerings. Exactly one of birdPeerConfig /
// bird6PeerConfig should be non-empty. Returns the container's BGP source IP
// (its kind-network IPv4 for the v4 case, the fixed 2001:20::20 for v6).
// Mirrors utils.py:start_external_node_with_bgp.
func StartExternalNodeWithBGP(t testing.TB, name, birdPeerConfig, bird6PeerConfig string) string {
	t.Helper()

	// Log available disk space, matching the Python helper's diagnostics.
	_, _ = Run(t, "df -h", RunOptions{AllowFail: true})

	// Privileged so the container can set routes.
	MustRun(t, fmt.Sprintf("docker run -d --privileged --net=kind --name %s %s", name, RouterImage))

	// The image may still be downloading; retry until the container responds.
	err := RetryUntilSuccess(t, 60*time.Second, func() error {
		_, err := Run(t, "docker exec "+name+" df -h", RunOptions{AllowFail: true, SuppressErrLog: true})
		return err
	})
	if err != nil {
		t.Fatalf("external node %s did not become ready: %v", name, err)
	}

	// Install tooling and enable L4 ECMP hashing.
	MustRun(t, "docker exec "+name+" apk add --no-cache curl iproute2")
	MustRun(t, "docker exec "+name+" sysctl -w net.ipv4.fib_multipath_hash_policy=1")

	// Allow ECMP route merging in BIRD's kernel protocol.
	MustRun(t, "docker exec "+name+" sed -i '/protocol kernel {/a merge paths on;' /etc/bird.conf")
	MustRun(t, "docker exec "+name+" sed -i '/protocol kernel {/a merge paths on;' /etc/bird6.conf")

	var birdyIP string
	switch {
	case birdPeerConfig != "":
		birdyIP = strings.TrimSpace(MustRun(t, fmt.Sprintf(
			"docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s", name)))
		writeBirdPeers(t, name, "/etc/bird/peers.conf", birdPeerConfig, birdyIP)
		MustRun(t, "docker exec "+name+" birdcl configure")
	case bird6PeerConfig != "":
		birdyIP = "2001:20::20"
		MustRun(t, "docker exec "+name+" sysctl -w net.ipv6.conf.all.disable_ipv6=0")
		MustRun(t, "docker exec "+name+" sysctl -w net.ipv6.conf.all.forwarding=1")
		// Best-effort: older kernels lack the v6 multipath hash setting, and
		// we don't test v6 ECMP in detail.
		_, _ = Run(t, "docker exec "+name+" sysctl -w net.ipv6.fib_multipath_hash_policy=1",
			RunOptions{AllowFail: true})
		MustRun(t, fmt.Sprintf("docker exec %s ip -6 a a %s/64 dev eth0", name, birdyIP))
		writeBirdPeers(t, name, "/etc/bird6/peers.conf", bird6PeerConfig, birdyIP)
		MustRun(t, "docker exec "+name+" birdcl6 configure")
	}
	return birdyIP
}

// writeBirdPeers substitutes the local IP into the peer config and writes it
// into the container at destPath via `docker cp` through a temp file.
func writeBirdPeers(t testing.TB, container, destPath, peerConfig, localIP string) {
	t.Helper()
	rendered := strings.ReplaceAll(peerConfig, "ip@local", localIP)
	tmp, err := os.CreateTemp("", "peers-*.conf")
	if err != nil {
		t.Fatalf("creating temp peers file: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(rendered); err != nil {
		t.Fatalf("writing temp peers file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("closing temp peers file: %v", err)
	}
	MustRun(t, fmt.Sprintf("docker cp %s %s:%s", tmp.Name(), container, destPath))
}

// CopyTextToExternalNode writes content into a file inside a docker container,
// mirroring the `cat <<EOF | docker exec -i ... sh -c "cat > file"` pattern.
func CopyTextToExternalNode(t testing.TB, container, destPath, content string) {
	t.Helper()
	cmd := fmt.Sprintf("docker exec -i %s sh -c 'cat > %s'", container, destPath)
	if _, err := runWithStdin(t, cmd, content); err != nil {
		t.Fatalf("writing %s into container %s: %v", destPath, container, err)
	}
}

// ExternalNodeRoutes returns the routing table of an external docker node.
// Mirrors test_base.py:get_routes (TestBase uses v4, TestBaseV6 uses v6).
func ExternalNodeRoutes(t testing.TB, container string, v6 bool) string {
	t.Helper()
	flag := ""
	if v6 {
		flag = "-6 "
	}
	return MustRun(t, fmt.Sprintf("docker exec %s ip %sr", container, flag))
}

// Curl curls hostname from inside a docker container (default kube-node-extra).
// Mirrors utils.py:curl. IPv6 literals are bracketed.
func Curl(t testing.TB, container, hostname string) (string, error) {
	t.Helper()
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	return Run(t, fmt.Sprintf("docker exec %s curl --connect-timeout 2 -m 3 %s", container, hostname))
}

// ----------------------------------------------------------------------------
// Pods.

// Pod wraps a created pod and exposes the lifecycle/status helpers that
// test_base.py:Pod provided. The pod is created via client-go from a fully
// specified corev1.Pod (the test builds the spec).
type Pod struct {
	t         testing.TB
	Name      string
	Namespace string

	ip       string
	ipv6     string
	hostIP   string
	nodeName string
}

// NewPod creates the given pod via client-go and returns a handle. The caller
// owns deletion (typically via t.Cleanup(pod.Delete)).
func NewPod(t testing.TB, pod *corev1.Pod) *Pod {
	t.Helper()
	cs := K8sClient(t)
	created, err := cs.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating pod %s/%s: %v", pod.Namespace, pod.Name, err)
	}
	return &Pod{t: t, Name: created.Name, Namespace: created.Namespace}
}

// Delete removes the pod (best effort).
func (p *Pod) Delete() {
	p.t.Helper()
	err := K8sClient(p.t).CoreV1().Pods(p.Namespace).Delete(context.Background(), p.Name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		p.t.Logf("deleting pod %s/%s: %v", p.Namespace, p.Name, err)
	}
}

// WaitReady blocks until the pod's Ready condition is True.
func (p *Pod) WaitReady() {
	p.t.Helper()
	WaitForPodReady(p.t, p.Namespace, p.Name, 60*time.Second)
}

// IP returns (and caches) the pod's primary IPv4 address, waiting up to 30s.
func (p *Pod) IP() string {
	p.t.Helper()
	if p.ip == "" {
		p.ip = p.waitForField("podIP", func(pod *corev1.Pod) string { return pod.Status.PodIP })
	}
	return p.ip
}

// IPv6 returns (and caches) the pod's IPv6 address, waiting up to 30s.
func (p *Pod) IPv6() string {
	p.t.Helper()
	if p.ipv6 == "" {
		p.ipv6 = p.waitForField("podIPv6", func(pod *corev1.Pod) string {
			for _, ip := range pod.Status.PodIPs {
				if strings.Contains(ip.IP, ":") {
					return ip.IP
				}
			}
			return ""
		})
	}
	return p.ipv6
}

// HostIP returns (and caches) the pod's host IP.
func (p *Pod) HostIP() string {
	p.t.Helper()
	if p.hostIP == "" {
		p.hostIP = p.waitForField("hostIP", func(pod *corev1.Pod) string { return pod.Status.HostIP })
	}
	return p.hostIP
}

// NodeName returns (and caches) the node the pod is scheduled on.
func (p *Pod) NodeName() string {
	p.t.Helper()
	if p.nodeName == "" {
		p.nodeName = p.waitForField("nodeName", func(pod *corev1.Pod) string { return pod.Spec.NodeName })
	}
	return p.nodeName
}

func (p *Pod) waitForField(what string, extract func(*corev1.Pod) string) string {
	p.t.Helper()
	cs := K8sClient(p.t)
	var val string
	err := RetryUntilSuccess(p.t, 30*time.Second, func() error {
		pod, err := cs.CoreV1().Pods(p.Namespace).Get(context.Background(), p.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		val = extract(pod)
		if val == "" {
			return fmt.Errorf("pod %s/%s has no %s yet", p.Namespace, p.Name, what)
		}
		return nil
	})
	if err != nil {
		p.t.Fatalf("pod %s/%s never reported %s: %v", p.Namespace, p.Name, what, err)
	}
	return val
}

// Execute runs a command in the pod's first container. Mirrors Pod.execute.
func (p *Pod) Execute(cmd string) string {
	p.t.Helper()
	return MustExecInPod(p.t, p.Namespace, p.Name, cmd)
}

// CopyInto writes content into destPath inside the pod's first container,
// the client-go equivalent of `kubectl cp`.
func (p *Pod) CopyInto(content, destPath string) {
	p.t.Helper()
	if _, err := execInPodStdin(p.t, p.Namespace, p.Name, []string{"sh", "-c", "cat > " + destPath}, content); err != nil {
		p.t.Fatalf("copying into pod %s/%s:%s: %v", p.Namespace, p.Name, destPath, err)
	}
}

// MustExecInPod is ExecInPod that fails the test on error.
func MustExecInPod(t testing.TB, namespace, podName, command string, opts ...RunOptions) string {
	t.Helper()
	out, err := ExecInPod(t, namespace, podName, command, opts...)
	if err != nil {
		t.Fatalf("exec in pod %s/%s (%q): %v", namespace, podName, command, err)
	}
	return out
}

// ----------------------------------------------------------------------------
// Exec with stdin.

// runWithStdin runs `sh -c <command>` feeding stdin, returning stdout.
func runWithStdin(t testing.TB, command, stdin string) (string, error) {
	t.Helper()
	t.Logf("[%s] (stdin) %s", time.Now().Format(time.RFC3339), command)
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("command %q failed: %w (stderr: %s)", command, err, stderr.String())
	}
	return stdout.String(), nil
}

// CalicoctlApply runs `calicoctl apply -f -`, feeding the given YAML/JSON on
// stdin. Used for Calico v3 resources (e.g. the aggregated Node API) that are
// not in the controller-runtime client's scheme.
func CalicoctlApply(t testing.TB, content string) {
	t.Helper()
	if _, err := runWithStdin(t, "calico ctl --allow-version-mismatch apply -f -", content); err != nil {
		t.Fatalf("calicoctl apply failed: %v", err)
	}
}

// ExecInPodStdin runs argv in the named pod's first container, feeding stdin to
// the remote process and returning its stdout. Used for `kubectl cp`-style
// file copies and for tools (e.g. scapy) that read a script from stdin.
func ExecInPodStdin(t testing.TB, namespace, podName string, argv []string, stdin string) (string, error) {
	t.Helper()
	return execInPodStdin(t, namespace, podName, argv, stdin)
}

func execInPodStdin(t testing.TB, namespace, podName string, argv []string, stdin string) (string, error) {
	t.Helper()
	cs := K8sClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pod, err := cs.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if len(pod.Spec.Containers) == 0 {
		return "", fmt.Errorf("pod %s/%s has no containers", namespace, podName)
	}
	container := pod.Spec.Containers[0].Name

	req := cs.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   argv,
			Stdin:     stdin != "",
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(K8sRestConfig(t), "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("building SPDY executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	streamOpts := remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}
	if stdin != "" {
		streamOpts.Stdin = strings.NewReader(stdin)
	}
	err = executor.StreamWithContext(ctx, streamOpts)
	if err != nil {
		return stdout.String(), fmt.Errorf("exec %v in pod %s/%s failed: %w (stderr: %s)",
			argv, namespace, podName, err, stderr.String())
	}
	return stdout.String(), nil
}
