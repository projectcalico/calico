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

package status

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	certV1 "k8s.io/api/certificates/v1"
	certV1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
)

var log = logf.Log.WithName("status_manager")

const (
	// terminationReasonError is the reason string the container runtime sets on
	// ContainerStateTerminated when the container exits with a non-zero exit code.
	terminationReasonError = "Error"

	// exitCodeSIGKILL is the exit code for a container killed by SIGKILL (128 + 9).
	// The kubelet sends SIGKILL when a liveness probe fails, but other actors (OOM
	// killer, manual kill) can also produce this code.
	exitCodeSIGKILL = 137

	// Container waiting reason strings. These are set by the container runtime and
	// kubelet; Kubernetes does not define constants for them.
	waitingCrashLoopBackOff = "CrashLoopBackOff"
	waitingImagePullBackOff = "ImagePullBackOff"
	waitingErrImagePull     = "ErrImagePull"

	// deploymentRevisionAnnotation records the revision number of a ReplicaSet
	// within its owning Deployment. Set by the deployment controller; Kubernetes
	// does not export a constant for it.
	deploymentRevisionAnnotation = "deployment.kubernetes.io/revision"

	// defaultReadinessGracePeriod is how long a running pod may stay unready
	// before we consider it failing, used for pods whose containers define no
	// readiness probe. It also acts as a floor for the probe-derived grace
	// period (see readinessGracePeriod), so we never flag a pod more
	// aggressively than this. This avoids tripping Degraded for pods that are
	// only briefly unready during a rolling update.
	defaultReadinessGracePeriod = 60 * time.Second

	// Kubelet defaults for probe timing fields, applied when a probe leaves them
	// unset. The API server fills these in for real pods, but we default
	// defensively so the derivation is correct for any pod object.
	defaultProbePeriodSeconds    = 10
	defaultProbeTimeoutSeconds   = 1
	defaultProbeFailureThreshold = 3

	customOverridesAnnotation = "operator.tigera.io/custom-overrides"
)

// hasOverride checks if the workload has a specific override type configured.
func hasOverride(annotations map[string]string, overrideType string) bool {
	val, ok := annotations[customOverridesAnnotation]
	if !ok {
		return false
	}
	for _, t := range strings.Split(val, ",") {
		if t == overrideType {
			return true
		}
	}
	return false
}

type podIssueSeverity int

const (
	severityProgressing podIssueSeverity = iota
	severityFailing
)

// podIssueType defines the category of a pod issue. The enum order determines display
// priority when issues compete for the 3-slot cap in summarizeIssues.
type podIssueType int

const (
	issueCrashLoopBackOff podIssueType = iota
	issueImagePull
	issueTerminated
	issuePodFailed
	issueNotReady
	issuePending
)

// podIssue represents a single diagnosed problem with a pod.
type podIssue struct {
	severity  podIssueSeverity
	issueType podIssueType
	message   string

	// workload identifies the owning workload (e.g. `DaemonSet "calico-system/calico-node"`).
	// It scopes dedup and the per-workload cap in summarizeIssues so issues from
	// different workloads aren't merged together.
	workload string

	// isOldRevision is true if the pod belongs to an old revision during a rollout.
	isOldRevision bool

	// terminationReason and exitCode provide dedup granularity within an issue type.
	terminationReason string
	exitCode          int32
}

// key returns a deduplication key for this issue. Issues with the same key are grouped
// together in summarizeIssues, so that e.g. 10 pods all OOMKilled produce one message
// with "(10 pods affected)" rather than 10 separate messages.
func (p podIssue) key() string {
	return fmt.Sprintf("%s:%d:%s:%d", p.workload, p.issueType, p.terminationReason, p.exitCode)
}

// maxIssuesToReport is the maximum number of distinct issue types reported per workload.
// Beyond this cap, additional issues are dropped to keep messages concise.
const maxIssuesToReport = 3

// summarizeIssues deduplicates, prioritizes, and caps a list of pod issues into
// human-readable failing and progressing message slices. Issues are grouped by
// workload so each workload independently gets up to maxIssuesToReport reasons.
func summarizeIssues(issues []podIssue) (failing []string, progressing []string) {
	if len(issues) == 0 {
		return nil, nil
	}

	// Sort: by workload (stable groups), then new-revision first, then by issue
	// type priority (enum order).
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].workload != issues[j].workload {
			return issues[i].workload < issues[j].workload
		}
		if issues[i].isOldRevision != issues[j].isOldRevision {
			return !issues[i].isOldRevision
		}
		return issues[i].issueType < issues[j].issueType
	})

	// Group by key. First occurrence provides the message; count tracks duplicates.
	// The key includes the workload, so dedup is per-workload.
	type issueGroup struct {
		issue podIssue
		count int
	}
	seen := map[string]int{}
	var groups []issueGroup
	for _, iss := range issues {
		k := iss.key()
		if idx, ok := seen[k]; ok {
			groups[idx].count++
			continue
		}
		seen[k] = len(groups)
		groups = append(groups, issueGroup{issue: iss, count: 1})
	}

	// Cap at maxIssuesToReport unique reasons per workload.
	perWorkload := map[string]int{}
	for _, g := range groups {
		if perWorkload[g.issue.workload] >= maxIssuesToReport {
			continue
		}
		perWorkload[g.issue.workload]++

		msg := g.issue.message
		if g.count > 1 {
			msg += fmt.Sprintf(" (%d pods affected)", g.count)
		}
		if g.issue.isOldRevision {
			msg += " (old revision)"
		}
		if g.issue.severity == severityFailing {
			failing = append(failing, msg)
		} else {
			progressing = append(progressing, msg)
		}
	}
	return failing, progressing
}

// StatusManager manages the status for a single controller and component, and reports the status via
// a TigeraStatus API object. The status manager uses the following conditions/states to represent the
// component's current status:
//
//   - Available: The component is successfully running. All pods launched by the component are healthy.
//     An upgrade may or may not be occurring.
//   - Progressing: A state change is occurring. It may be that the component is being installed for the
//     first time, or being upgraded to a new configuration or version.
//   - Degraded: The component is not running the desired state and is not progressing towards it. Either the
//     component has not been installed, has been updated with invalid configuration, or has crashed.
//
// Each of these states can be set independently of each other. For example, a component can be both available and
// degraded if it is running successfully but a configuration change has resulted in a configuration that cannot
// be actioned.
type StatusManager interface {
	Run(ctx context.Context)
	OnCRFound()
	OnCRNotFound()
	AddDaemonsets(dss []types.NamespacedName)
	AddDeployments(deps []types.NamespacedName)
	AddStatefulSets(sss []types.NamespacedName)
	AddCronJobs(cjs []types.NamespacedName)
	AddCertificateSigningRequests(name string, labels map[string]string)
	RemoveDaemonsets(dss ...types.NamespacedName)
	RemoveDeployments(dps ...types.NamespacedName)
	RemoveStatefulSets(sss ...types.NamespacedName)
	RemoveCronJobs(cjs ...types.NamespacedName)
	RemoveCertificateSigningRequests(name string)
	SetDegraded(reason operator.TigeraStatusReason, msg string, err error, log logr.Logger)
	ClearDegraded()
	SetWarning(key string, msg string)
	ClearWarning(key string)
	IsAvailable() bool
	IsProgressing() bool
	IsDegraded() bool
	ReadyToMonitor()
	SetMetaData(meta *metav1.ObjectMeta)
}

type statusManager struct {
	client                    client.Client
	component                 string
	daemonsets                map[string]types.NamespacedName
	deployments               map[string]types.NamespacedName
	statefulsets              map[string]types.NamespacedName
	cronjobs                  map[string]types.NamespacedName
	certificatestatusrequests map[string]map[string]string
	lock                      sync.Mutex
	enabled                   *bool
	kubernetesVersion         *common.VersionInfo

	// Track degraded state as set by external controllers.
	degraded               bool
	explicitDegradedMsg    string
	explicitDegradedReason operator.TigeraStatusReason

	// warnings stores warning messages keyed by component/secret name.
	warnings map[string]string

	// Keep track of currently calculated status.
	progressing []string
	failing     []string

	// readyToMonitor tells the status manager that it's ready to monitor the resources that it's been told to monitor,
	// if there are any, and report statuses based on the state of those resources.
	readyToMonitor bool
	hasSynced      bool

	// crExists tracks whether the status manager believes the CR to exist or not. It's used
	// to determine whether we need to call Delete() on the object, without sending unnecessary
	// get/delete calls to the API server.
	crExists bool

	observedGeneration int64
}

func New(client client.Client, component string, kubernetesVersion *common.VersionInfo) StatusManager {
	// Best-effort initialization of CR status by checking for its existence.
	crExists := true
	ts := &operator.TigeraStatus{}
	err := client.Get(context.TODO(), types.NamespacedName{Name: component}, ts)
	if err != nil && errors.IsNotFound(err) {
		// CR doesn't exist. If we hit any other type of error, we'll assume the CR does
		// exist. This may result in one unnecessary delete call if the resource in fact doesn't exist,
		// but we can't assume the object has been deleted without hard evidence.
		crExists = false
	}

	return &statusManager{
		client:                    client,
		component:                 component,
		daemonsets:                make(map[string]types.NamespacedName),
		deployments:               make(map[string]types.NamespacedName),
		statefulsets:              make(map[string]types.NamespacedName),
		cronjobs:                  make(map[string]types.NamespacedName),
		certificatestatusrequests: make(map[string]map[string]string),
		warnings:                  make(map[string]string),
		kubernetesVersion:         kubernetesVersion,
		crExists:                  crExists,
	}
}

func (m *statusManager) updateStatus() {
	// If we haven't queried the CR then nothing to do
	if !m.isInitialized() {
		return
	}

	if m.enabled != nil && !*m.enabled {
		// This status manager is explicitly disabled, because the controller has called OnCRNotFound.
		// Remove any TigeraStatus object that had previously been created, and skip updating the status.
		m.removeTigeraStatus()
		return
	}
	// This status manager is enabled. Perform a sync.

	// Unless we've been given an explicit degraded reason we are not ready to start reporting statuses until
	// ReadyToMonitor has been called by the owner of the status manager. This means there's no point in syncing
	// the state.
	if m.readyToMonitor {
		m.syncState()

		// We've collected knowledge about the current state of the objects we're monitoring.
		// Now, use that to update the TigeraStatus object for this manager.
		available := m.IsAvailable()
		availableMsg := m.availableMessage()
		if available {
			m.setAvailable(operator.AllObjectsAvailable, availableMsg)
		} else {
			m.clearAvailable()
		}

		if m.IsProgressing() {
			m.setProgressing(operator.ResourceNotReady, m.progressingMessage())
		} else {
			if available {
				m.clearProgressingWithReason(operator.AllObjectsAvailable, availableMsg)
			} else {
				m.clearProgressing()
			}
		}

		if m.IsDegraded() {
			m.setDegraded(m.degradedReason(), m.degradedMessage())
		} else {
			if available {
				m.clearDegradedWithReason(operator.AllObjectsAvailable, availableMsg)
			} else {
				m.clearDegraded()
			}
		}
	} else {
		log.V(2).WithName(m.component).Info("Status manager is not ready to report component statuses.")

		// If we've been given an explicit degraded reason then it should be reported even if readyToMonitor is false,
		// as this degraded reason may be the reason why we're not ready to monitor.
		if m.isExplicitlyDegraded() {
			m.setDegraded(m.degradedReason(), m.degradedMessage())
		} else {
			m.clearDegraded()
		}
	}
}

func (m *statusManager) isExplicitlyDegraded() bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.degraded
}

// Run starts the status manager state monitoring routine.
func (m *statusManager) Run(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		// Loop forever, periodically checking dependent objects for their state.
		for {
			m.updateStatus()

			select {
			case <-ticker.C:
				continue
			case <-ctx.Done():
				log.WithName(m.component).Info("Status manager is stopping")
				return
			}
		}
	}()
}

// ReadyToMonitor signals that this Status Manager should start evaluating the resources it knows about and report
// if the availability of the component based on the statuses of those monitored resources.
//
// If there are no resources to monitor, then by default this component is available (all 0 resources for this component
// are healthy). One caveat to the default when there are no resources to monitor is if the component has a degraded
// status explicitly set.
func (m *statusManager) ReadyToMonitor() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.readyToMonitor = true
}

// OnCRFound indicates to the status manager that it should start reporting status. Until called,
// the status manager will be be in a "dormant" state, and will not write status to the API.
// Call this function from a controller once it has first received an instance of its CRD.
func (m *statusManager) OnCRFound() {
	m.lock.Lock()
	defer m.lock.Unlock()
	t := true
	m.enabled = &t
}

// OnCRNotFound indicates that the CR managed by the parent controller has not been found. The
// status manager will clear its state.
func (m *statusManager) OnCRNotFound() {
	m.ClearDegraded()
	m.clearAvailable()
	m.clearProgressing()
	m.lock.Lock()
	defer m.lock.Unlock()
	f := false
	m.enabled = &f
	m.progressing = []string{}
	m.failing = []string{}
	m.daemonsets = make(map[string]types.NamespacedName)
	m.deployments = make(map[string]types.NamespacedName)
	m.statefulsets = make(map[string]types.NamespacedName)
	m.cronjobs = make(map[string]types.NamespacedName)
	m.warnings = make(map[string]string)
}

// AddDaemonsets tells the status manager to monitor the health of the given daemonsets.
func (m *statusManager) AddDaemonsets(dss []types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, ds := range dss {
		m.daemonsets[ds.String()] = ds
	}
}

// AddDeployments tells the status manager to monitor the health of the given deployments.
func (m *statusManager) AddDeployments(deps []types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, dep := range deps {
		m.deployments[dep.String()] = dep
	}
}

// AddStatefulSets tells the status manager to monitor the health of the given statefulsets.
func (m *statusManager) AddStatefulSets(sss []types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, ss := range sss {
		m.statefulsets[ss.String()] = ss
	}
}

// AddCronJobs tells the status manager to monitor the health of the given cronjobs.
func (m *statusManager) AddCronJobs(cjs []types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, cj := range cjs {
		m.cronjobs[cj.String()] = cj
	}
}

// AddCertificateSigningRequests tells the status manager to monitor the health of the given CertificateSigningRequests.
func (m *statusManager) AddCertificateSigningRequests(name string, labels map[string]string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.certificatestatusrequests[name] = labels
}

// RemoveDaemonsets tells the status manager to stop monitoring the health of the given daemonsets
func (m *statusManager) RemoveDaemonsets(dss ...types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, ds := range dss {
		delete(m.daemonsets, ds.String())
	}
}

// RemoveDeployments tells the status manager to stop monitoring the health of the given deployments.
func (m *statusManager) RemoveDeployments(dps ...types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, dp := range dps {
		delete(m.deployments, dp.String())
	}
}

// RemoveStatefulSets tells the status manager to stop monitoring the health of the given statefulsets.
func (m *statusManager) RemoveStatefulSets(sss ...types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, ss := range sss {
		delete(m.statefulsets, ss.String())
	}
}

// RemoveCronJobs tells the status manager to stop monitoring the health of the given cronjobs.
func (m *statusManager) RemoveCronJobs(cjs ...types.NamespacedName) {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, cj := range cjs {
		delete(m.cronjobs, cj.String())
	}
}

// RemoveCertificateSigningRequests tells the status manager to stop monitoring the health of the given CertificateSigningRequests.
func (m *statusManager) RemoveCertificateSigningRequests(name string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.certificatestatusrequests, name)
}

// SetDegraded sets degraded state with the provided reason and message.
func (m *statusManager) SetDegraded(reason operator.TigeraStatusReason, msg string, err error, log logr.Logger) {
	log.WithValues("reason", string(reason)).Error(err, msg)
	errormsg := ""
	if err != nil {
		errormsg = err.Error()
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.degraded = true
	m.explicitDegradedReason = reason
	if errormsg != "" {
		m.explicitDegradedMsg = fmt.Sprintf("%s: %s", msg, errormsg)
	} else {
		m.explicitDegradedMsg = msg
	}
}

// ClearDegraded clears degraded state.
func (m *statusManager) ClearDegraded() {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.degraded = false
	m.explicitDegradedReason = ""
	m.explicitDegradedMsg = ""
}

// SetWarning sets a warning message for the given key. Warnings are appended to the Available
// condition message so they are visible in `kubectl get tigerastatus`.
func (m *statusManager) SetWarning(key string, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.warnings[key] = msg
}

// ClearWarning removes the warning for the given key.
func (m *statusManager) ClearWarning(key string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.warnings, key)
}

// warningMessage returns all warning messages joined by "; ", or empty if there are none.
func (m *statusManager) warningMessage() string {
	m.lock.Lock()
	defer m.lock.Unlock()
	if len(m.warnings) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m.warnings))
	for k := range m.warnings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	msgs := make([]string, 0, len(keys))
	for _, k := range keys {
		msgs = append(msgs, m.warnings[k])
	}
	return strings.Join(msgs, "; ")
}

// IsAvailable returns true if the component is available and false otherwise.
func (m *statusManager) IsAvailable() bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	// If we're not ready to monitor or haven't synced then we're not ready to report a status base on the status of the
	// known resources.
	if !m.readyToMonitor || !m.hasSynced {
		return false
	}

	if m.degraded {
		return false
	}

	// If there are no resources to monitor then this is always true, which is by design.
	return len(m.failing) == 0 && len(m.progressing) == 0
}

// IsProgressing returns true if the component is progressing and false otherwise.
func (m *statusManager) IsProgressing() bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	// If we're not ready to monitor or haven't synced then we're not ready to report a status base on the status of the
	// known resources.
	if !m.readyToMonitor || !m.hasSynced {
		return false
	}

	return len(m.progressing) != 0 && len(m.failing) == 0
}

// IsDegraded returns true if the component is degraded and false otherwise.
func (m *statusManager) IsDegraded() bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Controllers can explicitly set us degraded, which can be set even before we tell the status manager that it
	// should start monitoring resources.
	if m.degraded {
		return true
	}

	// If we're not ready to monitor or haven't synced then we're not ready to report a status base on the status of the
	// known resources.
	if !m.readyToMonitor || !m.hasSynced {
		return false
	}

	// We may be degraded due to failing pods.
	return len(m.failing) != 0
}

// syncState syncs the internal state of the k8s resources that the status manager has been told to monitor with that of
// the cluster.
func (m *statusManager) syncState() {
	m.lock.Lock()
	defer m.lock.Unlock()
	progressing := []string{}
	failing := []string{}

	// Accumulate per-pod issues across all watched workloads. Each issue is stamped
	// with its workload, and summarizeIssues groups/caps per-workload at the end.
	var podIssues []podIssue

	// For each daemonset, check its rollout status.
	for _, dsnn := range m.daemonsets {
		ds := &appsv1.DaemonSet{}
		err := m.client.Get(context.TODO(), dsnn, ds)
		if err != nil {
			if errors.IsNotFound(err) {
				failing = append(failing, fmt.Sprintf("DaemonSet %q not found", dsnn.String()))
			} else {
				log.WithValues("reason", err).Info("Failed to query daemonset")
			}
			continue
		}
		if ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled {
			progressing = append(progressing, fmt.Sprintf("DaemonSet %q update is rolling out (%d out of %d updated)", dsnn.String(), ds.Status.UpdatedNumberScheduled, ds.Status.DesiredNumberScheduled))
		} else if ds.Status.NumberUnavailable > 0 {
			progressing = append(progressing, fmt.Sprintf("DaemonSet %q is not available (awaiting %d nodes)", dsnn.String(), ds.Status.NumberUnavailable))
		} else if ds.Status.NumberAvailable == 0 && ds.Status.DesiredNumberScheduled != 0 {
			progressing = append(progressing, fmt.Sprintf("DaemonSet %q is not yet scheduled on any nodes", dsnn.String()))
		} else if ds.Generation > ds.Status.ObservedGeneration {
			progressing = append(progressing, fmt.Sprintf("DaemonSet %q update is being processed (generation %d, observed generation %d)", dsnn.String(), ds.Generation, ds.Status.ObservedGeneration))
		}

		// If all these are true then all expected pods are present and healthy
		// so we don't need to worry about any failed pods so continue.
		if ds.Generation == ds.Status.ObservedGeneration &&
			ds.Status.NumberMisscheduled == 0 &&
			ds.Status.NumberUnavailable == 0 &&
			ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable &&
			ds.Status.DesiredNumberScheduled == ds.Status.NumberReady {
			continue
		}

		revision := m.currentDaemonSetRevision(ds)
		podIssues = append(podIssues, m.diagnosePods(fmt.Sprintf("DaemonSet %q", dsnn.String()), ds.Spec.Selector, ds.Namespace, revision, ds.Annotations)...)
	}

	for _, depnn := range m.deployments {
		dep := &appsv1.Deployment{}
		err := m.client.Get(context.TODO(), depnn, dep)
		if err != nil {
			if errors.IsNotFound(err) {
				failing = append(failing, fmt.Sprintf("Deployment %q not found", depnn.String()))
			} else {
				log.WithValues("reason", err).Info("Failed to query deployment")
			}
			continue
		}
		if dep.Status.UnavailableReplicas > 0 {
			progressing = append(progressing, fmt.Sprintf("Deployment %q is not available (awaiting %d replicas)", depnn.String(), dep.Status.UnavailableReplicas))
		} else if dep.Status.AvailableReplicas == 0 {
			progressing = append(progressing, fmt.Sprintf("Deployment %q is not yet scheduled on any nodes", depnn.String()))
		} else if dep.Status.ObservedGeneration < dep.Generation {
			progressing = append(progressing, fmt.Sprintf("Deployment %q update is being processed (generation %d, observed generation %d)", depnn.String(), dep.Generation, dep.Status.ObservedGeneration))
		}

		replicas := int32(1)
		if dep.Spec.Replicas != nil {
			replicas = *dep.Spec.Replicas
		}
		// There could be old pods in the Errored, Terminated, or Completed state
		// but if the following are true then we don't need to worry about those
		// failed pods so continue.
		if dep.Status.ObservedGeneration == dep.Generation &&
			dep.Status.UnavailableReplicas == 0 &&
			replicas == dep.Status.AvailableReplicas &&
			replicas == dep.Status.ReadyReplicas {
			continue
		}

		revision := m.currentDeploymentRevision(dep)
		podIssues = append(podIssues, m.diagnosePods(fmt.Sprintf("Deployment %q", depnn.String()), dep.Spec.Selector, dep.Namespace, revision, dep.Annotations)...)
	}

	for _, depnn := range m.statefulsets {
		ss := &appsv1.StatefulSet{}
		err := m.client.Get(context.TODO(), depnn, ss)
		if err != nil {
			if errors.IsNotFound(err) {
				failing = append(failing, fmt.Sprintf("StatefulSet %q not found", depnn.String()))
			} else {
				log.WithValues("reason", err).Info("Failed to query statefulset")
			}
			continue
		}
		if *ss.Spec.Replicas != ss.Status.CurrentReplicas {
			progressing = append(progressing, fmt.Sprintf("Statefulset %q is not available (awaiting %d replicas)", depnn.String(), ss.Status.CurrentReplicas-*ss.Spec.Replicas))
		} else if ss.Status.ObservedGeneration < ss.Generation {
			progressing = append(progressing, fmt.Sprintf("Statefulset %q update is being processed (generation %d, observed generation %d)", ss.String(), ss.Generation, ss.Status.ObservedGeneration))
		}

		replicas := int32(1)
		if ss.Spec.Replicas != nil {
			replicas = *ss.Spec.Replicas
		}
		// There could be old pods in the Errored, Terminated, or Completed state
		// but if the following are true then we don't need to worry about those
		// failed pods so continue.
		if ss.Status.ObservedGeneration == ss.Generation &&
			replicas == ss.Status.CurrentReplicas &&
			replicas == ss.Status.ReadyReplicas &&
			replicas == ss.Status.UpdatedReplicas {
			continue
		}

		podIssues = append(podIssues, m.diagnosePods(fmt.Sprintf("StatefulSet %q", depnn.String()), ss.Spec.Selector, ss.Namespace, ss.Status.UpdateRevision, ss.Annotations)...)
	}

	for _, depnn := range m.cronjobs {
		cj := &batchv1.CronJob{}
		if err := m.client.Get(context.TODO(), depnn, cj); err != nil {
			if errors.IsNotFound(err) {
				failing = append(failing, fmt.Sprintf("CronJob %q not found", depnn.String()))
			} else {
				log.WithValues("reason", err).Info("Failed to query cronjobs")
			}
			continue
		}

		numFailed := 0
		for _, jref := range cj.Status.Active {
			j := &batchv1.Job{}
			if err := m.client.Get(context.TODO(), types.NamespacedName{Namespace: jref.Namespace, Name: jref.Name}, j); err != nil {
				log.WithValues("reason", err).Info("couldn't query cronjob job")
				continue
			}

			if j.Status.Failed > 0 {
				numFailed++
			}
		}

		if numFailed > 0 {
			failing = append(failing, "cronjob/"+cj.Name+" failed in ns '"+cj.Namespace+"'")
		}
	}

	for _, labels := range m.certificatestatusrequests {
		pending, err := hasPendingCSR(context.TODO(), m, labels)
		if err != nil {
			log.WithValues("error", err).Error(err, fmt.Sprintf("Unable to poll for CertificateSigningRequest(s) with labels value %v", labels))
		} else if pending {
			progressing = append(progressing, fmt.Sprintf("Waiting on CertificateSigningRequest(s) with labels %v to be approved", labels))
		}
	}

	// Summarize all pod-level issues collected from watched workloads into
	// human-readable messages and merge them into the workload-level results.
	podFailing, podProgressing := summarizeIssues(podIssues)
	failing = append(failing, podFailing...)
	progressing = append(progressing, podProgressing...)

	m.progressing = progressing
	m.failing = failing
	m.hasSynced = true
}

// isInitialized returns true if corresponding CR has been queried
func (m *statusManager) isInitialized() bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.enabled != nil
}

// removeTigeraStatus removes the TigeraStatus object controlled by this status manager, if it exists.
func (m *statusManager) removeTigeraStatus() {
	m.lock.Lock()
	defer m.lock.Unlock()
	if !m.crExists {
		// No CR to delete, so short-circuit.
		return
	}

	// Status manager is explicitly disabled. Delete the TigeraStatus CR if it exists.
	ts := &operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: m.component}}
	err := m.client.Delete(context.TODO(), ts)
	if err != nil && !errors.IsNotFound(err) {
		log.WithValues("reason", err).Info("Failed to remove TigeraStatus", "component", m.component)
	} else {
		// CR no longer exists.
		m.crExists = false
	}
}

// diagnosePods lists pods matching the selector and returns a podIssue for each
// unhealthy pod found. Each issue is stamped with the given workload identifier
// for downstream grouping. If currentRevision is non-empty, pods not matching
// that revision are marked as old-revision. workloadAnnotations carries the
// owning workload's annotations so override hints can be correlated with pod
// failures.
func (m *statusManager) diagnosePods(workload string, selector *metav1.LabelSelector, namespace string, currentRevision string, workloadAnnotations map[string]string) []podIssue {
	l := corev1.PodList{}
	s, err := metav1.LabelSelectorAsMap(selector)
	if err != nil {
		panic(err)
	}
	err = m.client.List(context.TODO(), &l, client.MatchingLabels(s), client.InNamespace(namespace))
	if err != nil {
		log.WithValues("reason", err).Info("Failed to list pods for diagnosis")
		return nil
	}

	var issues []podIssue
	for _, p := range l.Items {
		isOldRevision := currentRevision != "" && !podMatchesRevision(p, currentRevision)

		if p.Status.Phase == corev1.PodFailed {
			issues = append(issues, podIssue{
				workload:      workload,
				severity:      severityFailing,
				issueType:     issuePodFailed,
				message:       fmt.Sprintf("Pod %s/%s has failed", p.Namespace, p.Name),
				isOldRevision: isOldRevision,
			})
			continue
		}

		// Check init and regular container statuses for errors.
		if iss := diagnoseContainers(p, p.Status.InitContainerStatuses, isOldRevision, workloadAnnotations); len(iss) > 0 {
			for i := range iss {
				iss[i].workload = workload
			}
			issues = append(issues, iss...)
			continue
		}
		if iss := diagnoseContainers(p, p.Status.ContainerStatuses, isOldRevision, workloadAnnotations); len(iss) > 0 {
			for i := range iss {
				iss[i].workload = workload
			}
			issues = append(issues, iss...)
			continue
		}

		// Pending - check for scheduling failures.
		if p.Status.Phase == corev1.PodPending {
			msg := fmt.Sprintf("Pod %s/%s is pending", p.Namespace, p.Name)
			for _, cond := range p.Status.Conditions {
				if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
					if cond.Message != "" {
						msg += fmt.Sprintf(": %s", cond.Message)
					}
					break
				}
			}
			issues = append(issues, podIssue{
				workload:      workload,
				severity:      severityProgressing,
				issueType:     issuePending,
				message:       msg,
				isOldRevision: isOldRevision,
			})
			continue
		}

		// Running - check if passing readiness checks. We only flag a pod once
		// it has been unready for longer than the grace period, to minimize
		// false positives during rolling updates. The grace period is derived
		// from the pod's readiness probes so that slow-starting pods are not
		// flagged before their probes would have had a chance to pass.
		if p.Status.Phase == corev1.PodRunning {
			grace := readinessGracePeriod(p)
			for _, cond := range p.Status.Conditions {
				if cond.Type != corev1.ContainersReady || cond.Status != corev1.ConditionFalse {
					continue
				}
				// A zero LastTransitionTime means we can't tell how long the pod has been
				// unready, so don't flag it - kubelet sets this field in practice.
				if cond.LastTransitionTime.IsZero() {
					continue
				}
				if time.Since(cond.LastTransitionTime.Time) > grace {
					msg := fmt.Sprintf("Pod %s/%s is running but not ready", p.Namespace, p.Name)
					if hasOverride(workloadAnnotations, "readinessProbe") {
						msg += "; custom readiness probe configuration is in effect"
					}
					if hasOverride(workloadAnnotations, "startupProbe") {
						msg += "; custom startup probe configuration is in effect"
					}
					issues = append(issues, podIssue{
						workload:      workload,
						severity:      severityFailing,
						issueType:     issueNotReady,
						message:       msg,
						isOldRevision: isOldRevision,
					})
					break
				}
			}
		}
	}
	return issues
}

// readinessGracePeriod returns how long the given pod may remain unready before
// we treat it as failing. It is derived from the pod's startup and readiness
// probes: a pod that legitimately takes a while to become ready (long initial
// delay, lenient failure threshold, or a slow probe cadence) should not be
// flagged before its probes would normally have settled. The value is the
// worst-case settling time across all containers, floored at
// defaultReadinessGracePeriod so we never flag a pod more aggressively than the
// fixed default and so pods without probes still get a sensible grace period.
func readinessGracePeriod(p corev1.Pod) time.Duration {
	grace := defaultReadinessGracePeriod
	for _, c := range p.Spec.Containers {
		// Kubelet holds off readiness until the startup probe passes, so the budgets add.
		d := probeSettlingTime(c.StartupProbe) + probeSettlingTime(c.ReadinessProbe)
		if d > grace {
			grace = d
		}
	}
	return grace
}

// probeSettlingTime returns the worst-case time for a probe to pass or give up,
// and zero for a nil probe.
func probeSettlingTime(probe *corev1.Probe) time.Duration {
	if probe == nil {
		return 0
	}

	period := probe.PeriodSeconds
	if period <= 0 {
		period = defaultProbePeriodSeconds
	}
	timeout := probe.TimeoutSeconds
	if timeout <= 0 {
		timeout = defaultProbeTimeoutSeconds
	}
	threshold := probe.FailureThreshold
	if threshold <= 0 {
		threshold = defaultProbeFailureThreshold
	}

	// Initial delay, plus failureThreshold attempts each costing period plus timeout.
	return time.Duration(probe.InitialDelaySeconds)*time.Second +
		time.Duration(threshold)*time.Duration(period+timeout)*time.Second
}

// diagnoseContainers checks a list of container statuses for known error states and
// returns a podIssue for each one found.
func diagnoseContainers(p corev1.Pod, statuses []corev1.ContainerStatus, isOldRevision bool, workloadAnnotations map[string]string) []podIssue {
	var issues []podIssue
	for _, c := range statuses {
		if c.State.Waiting != nil {
			switch c.State.Waiting.Reason {
			case waitingCrashLoopBackOff:
				msg := fmt.Sprintf("Pod %s/%s has crash looping container: %s", p.Namespace, p.Name, c.Name)
				var termReason string
				var exitCode int32
				if lt := c.LastTerminationState.Terminated; lt != nil {
					termReason = lt.Reason
					exitCode = lt.ExitCode
					if lt.Reason == terminationReasonError && lt.ExitCode == exitCodeSIGKILL {
						msg += " (exit code 137, possible liveness probe failure)"
						if hasOverride(workloadAnnotations, "livenessProbe") {
							msg += "; custom liveness probe configuration is in effect"
						}
					} else {
						msg += fmt.Sprintf(" (%s, exit code %d)", lt.Reason, lt.ExitCode)
						if lt.Reason == "OOMKilled" && hasOverride(workloadAnnotations, "resources") {
							msg += "; custom resource limits are in effect"
						}
					}
				}
				issues = append(issues, podIssue{
					severity:          severityFailing,
					issueType:         issueCrashLoopBackOff,
					message:           msg,
					isOldRevision:     isOldRevision,
					terminationReason: termReason,
					exitCode:          exitCode,
				})
			case waitingImagePullBackOff, waitingErrImagePull:
				issues = append(issues, podIssue{
					severity:      severityFailing,
					issueType:     issueImagePull,
					message:       fmt.Sprintf("Pod %s/%s failed to pull container image %q for container %s", p.Namespace, p.Name, c.Image, c.Name),
					isOldRevision: isOldRevision,
				})
			}
		}
		if c.State.Terminated != nil {
			if c.State.Terminated.Reason == terminationReasonError {
				issues = append(issues, podIssue{
					severity:      severityFailing,
					issueType:     issueTerminated,
					message:       fmt.Sprintf("Pod %s/%s has terminated container: %s", p.Namespace, p.Name, c.Name),
					isOldRevision: isOldRevision,
				})
			}
		}
	}
	return issues
}

// podMatchesRevision checks whether a pod belongs to the given revision.
// Works for DaemonSets and StatefulSets (controller-revision-hash label)
// and Deployments (pod-template-hash label).
func podMatchesRevision(p corev1.Pod, currentRevision string) bool {
	if hash, ok := p.Labels[appsv1.ControllerRevisionHashLabelKey]; ok {
		return hash == currentRevision
	}
	if hash, ok := p.Labels[appsv1.DefaultDeploymentUniqueLabelKey]; ok {
		return hash == currentRevision
	}
	return true
}

// currentDeploymentRevision returns the pod-template-hash of the active ReplicaSet
// for the given Deployment. Returns empty string if it cannot be determined.
// Only called when the Deployment is unhealthy. The List call goes through
// the controller-runtime informer cache, not directly to the API server.
func (m *statusManager) currentDeploymentRevision(dep *appsv1.Deployment) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rsList := &appsv1.ReplicaSetList{}
	s, err := metav1.LabelSelectorAsMap(dep.Spec.Selector)
	if err != nil {
		log.WithValues("reason", err).Info("Failed to parse deployment selector for revision lookup")
		return ""
	}
	err = m.client.List(ctx, rsList, client.MatchingLabels(s), client.InNamespace(dep.Namespace))
	if err != nil {
		log.WithValues("reason", err).Info("Failed to list ReplicaSets for revision lookup")
		return ""
	}

	// During a rolling update both the new and old ReplicaSets can have
	// Replicas > 0, so "has running pods" doesn't identify the active one.
	// The active ReplicaSet is the one with the highest revision, recorded in
	// the deployment.kubernetes.io/revision annotation - same idea as picking
	// the max ControllerRevision in currentDaemonSetRevision.
	var maxRevision int64
	var currentHash string
	for _, rs := range rsList.Items {
		// The Deployment selector can match ReplicaSets it doesn't own (e.g. from a
		// previous Deployment with the same selector). Filter to ReplicaSets owned
		// by this specific Deployment via the controller owner reference.
		if ref := metav1.GetControllerOf(&rs); ref == nil || ref.UID != dep.UID {
			continue
		}
		rev, err := strconv.ParseInt(rs.Annotations[deploymentRevisionAnnotation], 10, 64)
		if err != nil {
			continue
		}
		if rev > maxRevision {
			maxRevision = rev
			currentHash = rs.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
		}
	}
	return currentHash
}

// currentDaemonSetRevision returns the controller-revision-hash of the most recent
// ControllerRevision for the given DaemonSet. Returns empty string if it cannot be determined.
// Only called when the DaemonSet is unhealthy. The List call goes through
// the controller-runtime informer cache, not directly to the API server.
func (m *statusManager) currentDaemonSetRevision(ds *appsv1.DaemonSet) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	revList := &appsv1.ControllerRevisionList{}
	err := m.client.List(ctx, revList, client.InNamespace(ds.Namespace))
	if err != nil {
		log.WithValues("reason", err).Info("Failed to list ControllerRevisions for revision lookup")
		return ""
	}

	var maxRevision int64
	var currentHash string
	for _, rev := range revList.Items {
		// ControllerRevisions in the namespace are shared across all DaemonSets and
		// StatefulSets there. Filter to ones owned by this specific DaemonSet via
		// the controller owner reference.
		if ref := metav1.GetControllerOf(&rev); ref == nil || ref.UID != ds.UID {
			continue
		}
		if rev.Revision > maxRevision {
			maxRevision = rev.Revision
			currentHash = rev.Labels[appsv1.ControllerRevisionHashLabelKey]
		}
	}
	return currentHash
}

func (m *statusManager) set(retry bool, conditions ...operator.TigeraStatusCondition) {
	if m.enabled == nil || !*m.enabled {
		// Never set any conditions unless the status manager is enabled.
		return
	}

	var ts operator.TigeraStatus
	err := m.client.Get(context.TODO(), types.NamespacedName{Name: m.component}, &ts)
	isNotFound := errors.IsNotFound(err)
	if err != nil && !isNotFound {
		log.WithValues("reason", err).Info("Failed to get TigeraStatus", "component", m.component)
		return
	}

	if isNotFound {
		// Make a new one.
		ts = operator.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: m.component}}
	}

	// Make a copy for comparing later.
	old := ts.DeepCopy()

	// Go through each new condition. If we have an existing condition of the same type, then simply
	// update it. Otherwise add a new one.
	for _, condition := range conditions {
		found := false

		// set the CR's observedGeneration for tigerastatus condition
		if m.observedGeneration != 0 {
			condition.ObservedGeneration = m.observedGeneration
		}
		for i, c := range ts.Status.Conditions {
			if c.Type == condition.Type {
				// If the status has changed, update the transition time.
				condition.LastTransitionTime = c.LastTransitionTime
				if c.Status != condition.Status {
					condition.LastTransitionTime = metav1.NewTime(time.Now())
				}
				ts.Status.Conditions[i] = condition
				found = true
			}
		}
		if !found {
			condition.LastTransitionTime = metav1.NewTime(time.Now())
			ts.Status.Conditions = append(ts.Status.Conditions, condition)
		}
	}

	// If nothing has changed, we don't need to update in the API.
	if reflect.DeepEqual(ts.Status.Conditions, old.Status.Conditions) {
		return
	}

	// Update the object in the API, creating it if necessary.
	if isNotFound {
		if err = m.client.Create(context.TODO(), &ts); err != nil {
			log.WithValues("reason", err).Info("Failed to create tigera status")
		}
	} else {
		err = m.client.Status().Update(context.TODO(), &ts)
		if err != nil {
			if retry && errors.IsConflict(err) {
				log.WithValues("reason", err).V(1).Info("update to tigera status conflicted, retrying")
				m.set(false, conditions...)
			} else {
				log.WithValues("reason", err).Info("Failed to update tigera status")
			}
		}
	}
	m.crExists = true
}

func (m *statusManager) setAvailable(reason operator.TigeraStatusReason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentAvailable, Status: operator.ConditionTrue, Reason: string(reason), Message: msg},
	}
	m.set(true, conditions...)
}

func (m *statusManager) setDegraded(reason operator.TigeraStatusReason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentDegraded, Status: operator.ConditionTrue, Reason: string(reason), Message: msg},
	}
	m.set(true, conditions...)
}

func (m *statusManager) setProgressing(reason operator.TigeraStatusReason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentProgressing, Status: operator.ConditionTrue, Reason: string(reason), Message: msg},
	}
	m.set(true, conditions...)
}

func (m *statusManager) clearDegraded() {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentDegraded, Status: operator.ConditionFalse, Reason: string(operator.Unknown), Message: ""},
	}
	m.set(true, conditions...)
}

func (m *statusManager) clearProgressing() {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentProgressing, Status: operator.ConditionFalse, Reason: string(operator.Unknown), Message: ""},
	}
	m.set(true, conditions...)
}

func (m *statusManager) clearAvailable() {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentAvailable, Status: operator.ConditionFalse, Reason: string(operator.Unknown), Message: ""},
	}
	m.set(true, conditions...)
}

func (m *statusManager) availableMessage() string {
	msg := "All objects available"
	if w := m.warningMessage(); w != "" {
		msg = msg + "; " + w
	}
	return msg
}

func (m *statusManager) progressingMessage() string {
	m.lock.Lock()
	defer m.lock.Unlock()
	return strings.Join(m.progressing, "\n")
}

func (m *statusManager) degradedMessage() string {
	m.lock.Lock()
	defer m.lock.Unlock()
	msgs := []string{}
	if m.explicitDegradedMsg != "" {
		msgs = append(msgs, m.explicitDegradedMsg)
	}
	msgs = append(msgs, m.failing...)
	return strings.Join(msgs, "\n")
}

// This function should only be called if we are in a degraded state.
// Every path should return a non-empty string that can be used in
// the Condition Reason.
func (m *statusManager) degradedReason() operator.TigeraStatusReason {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.degraded {
		// Ensure we always have a reason that is non-empty
		if m.explicitDegradedReason == "" {
			return operator.Unknown
		}
		return m.explicitDegradedReason
	}
	if len(m.failing) != 0 {
		return operator.PodFailure
	}
	return operator.Unknown
}

func (m *statusManager) clearDegradedWithReason(reason operator.TigeraStatusReason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentDegraded, Status: operator.ConditionFalse, Reason: string(reason), Message: msg},
	}
	m.set(true, conditions...)
}

func (m *statusManager) clearProgressingWithReason(reason operator.TigeraStatusReason, msg string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	conditions := []operator.TigeraStatusCondition{
		{Type: operator.ComponentProgressing, Status: operator.ConditionFalse, Reason: string(reason), Message: msg},
	}
	m.set(true, conditions...)
}

func (m *statusManager) SetMetaData(meta *metav1.ObjectMeta) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.observedGeneration = meta.Generation
}

func hasPendingCSR(ctx context.Context, m *statusManager, labelMap map[string]string) (bool, error) {
	if m.kubernetesVersion.ProvidesCertV1API() {
		return hasPendingCSRUsingCertV1(ctx, m.client, labelMap)
	}
	// For k8s v1.19 onwards, certificate/v1beta1 will be deprecated and is planning to be removed on 1.22
	// Once in the future we stop support v1.18, we need to change the code to only use certificate/v1
	return hasPendingCSRUsingCertV1beta1(ctx, m.client, labelMap)
}

func hasPendingCSRUsingCertV1(ctx context.Context, cli client.Client, labelMap map[string]string) (bool, error) {
	csrs := &certV1.CertificateSigningRequestList{}
	selector := labels.SelectorFromSet(labelMap)
	err := cli.List(ctx, csrs, &client.ListOptions{LabelSelector: selector})
	if err != nil {
		return false, err
	}

	if len(csrs.Items) == 0 {
		return false, nil
	}

	for _, csr := range csrs.Items {
		if len(csr.Status.Conditions) == 0 {
			// No conditions means status is pending
			return true, nil
		}
		// no condition approved, means it is pending.
		for _, condition := range csr.Status.Conditions {
			if condition.Status == corev1.ConditionUnknown {
				return true, nil
			} else if condition.Type == certV1.CertificateApproved && csr.Status.Certificate == nil {
				return true, nil
			}
		}
	}
	return false, nil
}

func hasPendingCSRUsingCertV1beta1(ctx context.Context, cli client.Client, labelMap map[string]string) (bool, error) {
	csrs := &certV1beta1.CertificateSigningRequestList{}
	selector := labels.SelectorFromSet(labelMap)
	err := cli.List(ctx, csrs, &client.ListOptions{LabelSelector: selector})
	if err != nil {
		return false, err
	}

	if len(csrs.Items) == 0 {
		return false, nil
	}

	for _, csr := range csrs.Items {
		if len(csr.Status.Conditions) == 0 {
			// No conditions means status is pending
			return true, nil
		}
		// no condition approved, means it is pending.
		for _, condition := range csr.Status.Conditions {
			if condition.Status == corev1.ConditionUnknown {
				return true, nil
			} else if condition.Type == certV1beta1.CertificateApproved && csr.Status.Certificate == nil {
				return true, nil
			}
		}
	}
	return false, nil
}

// UpdateStatusCondition updates CR's status conditions from tigerastatus conditions.
func UpdateStatusCondition(statuscondition []metav1.Condition, conditions []operator.TigeraStatusCondition) []metav1.Condition {
	if statuscondition == nil {
		statuscondition = []metav1.Condition{}
	}

	for _, condition := range conditions {
		found := false

		ctype := string(condition.Type)
		if condition.Type == operator.ComponentAvailable {
			ctype = string(operator.ComponentReady)
		}

		status := metav1.ConditionUnknown
		switch condition.Status {
		case operator.ConditionTrue:
			status = metav1.ConditionTrue
		case operator.ConditionFalse:
			status = metav1.ConditionFalse
		}
		ic := metav1.Condition{
			Type:               ctype,
			Status:             status,
			LastTransitionTime: condition.LastTransitionTime,
			ObservedGeneration: condition.ObservedGeneration,
			Message:            condition.Message,
		}

		if len(condition.Reason) > 0 {
			ic.Reason = condition.Reason
		} else {
			ic.Reason = string(operator.Unknown)
		}

		for i, c := range statuscondition {
			if condition.Type == operator.ComponentAvailable && c.Type == string(operator.ComponentReady) ||
				condition.Type == operator.ComponentDegraded && c.Type == string(operator.ComponentDegraded) ||
				condition.Type == operator.ComponentProgressing && c.Type == string(operator.ComponentProgressing) {
				if !reflect.DeepEqual(c.Status, condition.Status) {
					ic.LastTransitionTime = metav1.NewTime(time.Now())
				}
				statuscondition[i] = ic
				found = true
			}
		}
		if !found {
			ic.LastTransitionTime = metav1.NewTime(time.Now())
			statuscondition = append(statuscondition, ic)
		}
	}
	return statuscondition
}
