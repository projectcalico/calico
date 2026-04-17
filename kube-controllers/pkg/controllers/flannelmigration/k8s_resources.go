// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
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

package flannelmigration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/drain"
)

// daemonset holds a collection of helper functions for Kubernetes daemonset.
type daemonset string

// Delete a daemonset and all dependents.
func (d daemonset) DeleteForeground(k8sClientset *kubernetes.Clientset, namespace string) error {
	policy := metav1.DeletePropagationForeground
	options := metav1.DeleteOptions{
		PropagationPolicy: &policy,
	}
	return k8sClientset.AppsV1().DaemonSets(namespace).Delete(context.Background(), string(d), options)
}

// Check if daemonset exists or not.
// Return true if not exists.
func (d daemonset) CheckNotExists(k8sClientset *kubernetes.Clientset, namespace string) (bool, error) {
	_, err := k8sClientset.AppsV1().DaemonSets(namespace).Get(context.Background(), string(d), metav1.GetOptions{})
	if apierrs.IsNotFound(err) {
		return true, nil
	}

	return false, err
}

// Get value of a label for daemonset.
// Return value if key exists.
func (d daemonset) getLabelValue(k8sClientset *kubernetes.Clientset, namespace, key string) (bool, string, error) {
	ds, err := k8sClientset.AppsV1().DaemonSets(namespace).Get(context.Background(), string(d), metav1.GetOptions{})
	if err != nil {
		return false, "", err
	}

	if val, ok := ds.Labels[key]; ok {
		return true, val, nil
	}

	return false, "", nil
}

// Get spec of a container from a daemonset.
func (d daemonset) getContainerSpec(k8sClientset *kubernetes.Clientset, namespace, containerName string) (*v1.Container, error) {
	ds, err := k8sClientset.AppsV1().DaemonSets(namespace).Get(context.Background(), string(d), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for _, c := range ds.Spec.Template.Spec.InitContainers {
		if c.Name == containerName {
			return &c, nil
		}
	}

	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == containerName {
			return &c, nil
		}
	}
	return nil, fmt.Errorf("no container with name %s found in daemonset", containerName)
}

// Get container image from a container spec.
func (d daemonset) GetContainerImage(k8sClientset *kubernetes.Clientset, namespace, containerName string) (string, error) {
	container, err := d.getContainerSpec(k8sClientset, namespace, containerName)
	if err != nil {
		return "", err
	}

	return container.Image, nil
}

// Get container env value.
func (d daemonset) GetContainerEnv(k8sClientset *kubernetes.Clientset, namespace, containerName, envName string) (string, error) {
	container, err := d.getContainerSpec(k8sClientset, namespace, containerName)
	if err != nil {
		return "", err
	}

	env := container.Env
	for _, e := range env {
		if e.Name == envName {
			return e.Value, nil
		}
	}

	return "", fmt.Errorf("no Env with name %s found in container %s", envName, containerName)
}

// Wait for daemonset to disappear.
func (d daemonset) WaitForDaemonsetNotFound(k8sClientset *kubernetes.Clientset, namespace string, interval, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, true, func(ctx context.Context) (bool, error) {
		_, err := k8sClientset.AppsV1().DaemonSets(namespace).Get(ctx, string(d), metav1.GetOptions{})
		if apierrs.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return true, err
		}
		// Daemonset still exists, retry.
		return false, nil
	})
}

// Remove node selectors from daemonset.
func (d daemonset) RemoveNodeSelector(k8sClientset *kubernetes.Clientset, namespace string, selector map[string]string) error {
	ds, err := k8sClientset.AppsV1().DaemonSets(namespace).Get(context.Background(), string(d), metav1.GetOptions{})
	if err != nil {
		return err
	}

	needUpdate := false
	for k, v := range selector {
		if currentVal, ok := ds.Spec.Template.Spec.NodeSelector[k]; ok && currentVal == v {
			delete(ds.Spec.Template.Spec.NodeSelector, k)
			needUpdate = true
		}
	}

	if needUpdate {
		_, err = k8sClientset.AppsV1().DaemonSets(namespace).Update(context.Background(), ds, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

// Add node selectors to daemonset.
// If node selectors has been set already, do nothing.
func (d daemonset) AddNodeSelector(k8sClientset *kubernetes.Clientset, namespace string, selector map[string]string) error {
	ds, err := k8sClientset.AppsV1().DaemonSets(namespace).Get(context.Background(), string(d), metav1.GetOptions{})
	if err != nil {
		return err
	}

	if ds.Spec.Template.Spec.NodeSelector == nil {
		ds.Spec.Template.Spec.NodeSelector = make(map[string]string)
	}

	needUpdate := false
	for k, v := range selector {
		if currentVal, ok := ds.Spec.Template.Spec.NodeSelector[k]; ok && currentVal == v {
			continue
		}
		ds.Spec.Template.Spec.NodeSelector[k] = v
		needUpdate = true
	}

	if needUpdate {
		_, err = k8sClientset.AppsV1().DaemonSets(namespace).Update(context.Background(), ds, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

// k8spod holds a collection of helper functions for Kubernetes pod.
type k8spod string

// Run a pod with a host path volume on specified node. Wait till it is completed.
// Return error with log if for any reason pod not completed successfully.
func (p k8spod) RunPodOnNodeTillComplete(k8sClientset *kubernetes.Clientset, namespace, imageName, nodeName, shellCmd, hostPath string, privileged, hostNetwork bool) (string, error) {
	podName := string(p)
	containerName := podName
	hostPathDirectory := v1.HostPathDirectory

	log.Infof("Create pod on node %s to run [ %s ].", nodeName, shellCmd)
	podSpec := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: podName + "-",
			Labels: map[string]string{
				"flannel-migration": nodeName,
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    containerName,
					Image:   imageName,
					Command: []string{"/bin/sh"},
					Args: []string{
						"-c",
						shellCmd,
					},
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "host-dir",
							MountPath: fmt.Sprintf("/host/%s", hostPath),
						},
					},
					SecurityContext: &v1.SecurityContext{Privileged: &privileged},
				},
			},
			Tolerations:   []v1.Toleration{{Operator: v1.TolerationOpExists}}, // Tolerate everything
			HostNetwork:   hostNetwork,
			NodeName:      nodeName,
			RestartPolicy: v1.RestartPolicyNever,
			Volumes: []v1.Volume{
				{
					Name: "host-dir",
					VolumeSource: v1.VolumeSource{
						HostPath: &v1.HostPathVolumeSource{
							Path: hostPath,
							Type: &hostPathDirectory,
						},
					},
				},
			},
		},
	}

	logs := ""
	pod, err := k8sClientset.CoreV1().Pods(namespace).Create(context.Background(), podSpec, metav1.CreateOptions{})
	if err != nil {
		return logs, err
	}

	err = waitForPodSuccessTimeout(k8sClientset, pod.Name, pod.Namespace, 1*time.Second, 5*time.Minute)
	if err != nil {
		log.WithError(err).Errorf("Error waiting for pod %s success or timeout.", pod.Name)

		// Trying to get pod log on error.
		var logErr error
		logs, logErr = getPodContainerLog(k8sClientset, namespace, pod.Name, containerName)
		log.WithError(logErr).Infof("Failed to get log. pod %s container %s.", pod.Name, containerName)
		return logs, err
	}

	// Delete pod if everything is fine. If not, leave pod running to get log manually.
	err = k8sClientset.CoreV1().Pods(namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
	if err != nil {
		return logs, err
	}

	return logs, nil
}

// Get Pod logs
func getPodContainerLog(k8sClientSet *kubernetes.Clientset, namespace, podName, containerName string) (string, error) {
	podLog, err := k8sClientSet.CoreV1().RESTClient().Get().
		Resource("pods").
		Namespace(namespace).
		Name(podName).SubResource("log").
		Param("container", containerName).
		Param("previous", "false").
		Do(context.Background()).
		Raw()
	if err != nil {
		return "", err
	}
	return string(podLog), err
}

// waitForPodSuccessTimeout returns nil if the pod reached state success, or an error if it reached failure or ran too long.
func waitForPodSuccessTimeout(k8sClientset *kubernetes.Clientset, podName, namespace string, interval, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, true, func(ctx context.Context) (bool, error) {
		pod, err := k8sClientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			// Cannot get pod yet, retry.
			return false, err
		}
		if pod.Status.Phase == v1.PodSucceeded {
			return true, nil
		}
		if pod.Status.Phase == v1.PodFailed {
			return true, fmt.Errorf("pod %s completed with failed status: %+v", podName, pod.Status)
		}
		// None of above, retry.
		return false, nil
	})
}

// k8snode holds a collection of helper functions for Kubernetes node.
type k8snode string

// Add node labels to node. Perform Get/Check/Update so that it always working on latest version.
// If node labels has been set already, do nothing.
func (n k8snode) addNodeLabels(k8sClientset *kubernetes.Clientset, labelMaps ...map[string]string) error {
	nodeName := string(n)
	return wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		node, err := k8sClientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := false
		for _, labels := range labelMaps {
			for k, v := range labels {
				if currentVal, ok := node.Labels[k]; ok && currentVal == v {
					continue
				}
				node.Labels[k] = v
				needUpdate = true
			}
		}

		if needUpdate {
			_, err := k8sClientset.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
			if err == nil {
				return true, nil
			}
			if !apierrs.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

// Remove node labels to node. Perform Get/Check/Update so that it always working on latest version.
// If node labels do not exist, do nothing.
func (n k8snode) removeNodeLabels(k8sClientset *kubernetes.Clientset, labelMaps ...map[string]string) error {
	nodeName := string(n)
	return wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
		node, err := k8sClientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		needUpdate := false
		for _, labels := range labelMaps {
			for k := range labels {
				if _, ok := node.Labels[k]; ok {
					delete(node.Labels, k)
					needUpdate = true
				}
			}
		}

		if needUpdate {
			_, err := k8sClientset.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
			if err == nil {
				return true, nil
			}
			if !apierrs.IsConflict(err) {
				return false, err
			}

			// Retry on update conflicts.
			return false, nil
		}

		// no update needed
		return true, nil
	})
}

// Start deletion process for pods on a node which satisfy a filter.
func (n k8snode) deletePodsForNode(k8sClientset *kubernetes.Clientset, filter func(pod *v1.Pod) bool) error {
	nodeName := string(n)
	podList, err := k8sClientset.CoreV1().Pods(metav1.NamespaceAll).List(context.Background(),
		metav1.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName}).String()})
	if err != nil {
		return err
	}

	for _, pod := range podList.Items {
		if filter(&pod) {
			err = k8sClientset.CoreV1().Pods(pod.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
			if err != nil && !apierrs.IsNotFound(err) {
				return err
			}
		}
	}

	return nil
}

func isPodRunningAndReady(pod *v1.Pod) bool {
	if pod == nil {
		log.Fatalf("isPodRunningAndReady received a nil pointer")
		return false
	}
	if pod.Status.Phase != v1.PodRunning {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == v1.PodReady && c.Status == v1.ConditionTrue {
			return true
		}
	}

	return false
}

// Wait for a pod becoming ready on a node.
func (n k8snode) waitPodReadyForNode(k8sClientset *kubernetes.Clientset, namespace string, interval, timeout time.Duration, label map[string]string) error {
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, true, func(context.Context) (bool, error) {
		nodeName := string(n)
		podList, err := k8sClientset.CoreV1().Pods(namespace).List(
			context.Background(),
			metav1.ListOptions{
				FieldSelector: fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName}).String(),
				LabelSelector: labels.SelectorFromSet(label).String(),
			},
		)
		if err != nil {
			// Something wrong, stop waiting
			return true, err
		}

		if len(podList.Items) == 0 {
			// No pod yet, retry
			return false, nil
		}

		if len(podList.Items) > 1 {
			// Multiple pods, stop waiting
			return true, fmt.Errorf("getting multiple pod with label %v on node %s", label, nodeName)
		}

		pod := podList.Items[0]
		if isPodRunningAndReady(&pod) {
			// Pod running and ready, stop waiting
			return true, nil
		}

		// Pod not ready yet, retry
		return false, nil
	})
}

// Execute command in a pod on a node. Get command output.
func (n k8snode) execCommandInPod(k8sClientset *kubernetes.Clientset, restConfig *rest.Config, namespace, containerName string, label map[string]string, args ...string) (string, error) {
	nodeName := string(n)
	var pod v1.Pod
	found := false
	for k, v := range label {
		podList, err := k8sClientset.CoreV1().Pods(namespace).List(
			context.Background(),
			metav1.ListOptions{
				FieldSelector: fields.SelectorFromSet(fields.Set{"spec.nodeName": nodeName}).String(),
				LabelSelector: labels.SelectorFromSet(map[string]string{k: v}).String(),
			},
		)
		if err != nil {
			return "", err
		}

		if len(podList.Items) == 1 {
			found = true
			pod = podList.Items[0]
			break
		}
	}

	if !found {
		// Cannot find pod.
		return "", fmt.Errorf("failed to execute command in pod. Cannot find pod with label in %v on node %s", label, nodeName)
	}

	if !isPodRunningAndReady(&pod) {
		// Pod is not running and ready.
		return "", fmt.Errorf("failed to execute command in pod. Pod %s is not ready", pod.Name)
	}

	req := k8sClientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&v1.PodExecOptions{
			Container: containerName,
			Command:   args,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to build SPDY executor for %s/%s: %w", namespace, pod.Name, err)
	}

	var stdout, stderr bytes.Buffer
	if err := executor.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		log.WithError(err).Errorf("Exec %s(%s) error. \n ---%v--- \nstdout:\n%s\nstderr:\n%s\n ------", pod.Name, containerName, args, stdout.String(), stderr.String())
		return "", err
	}

	log.Infof("Exec %s(%s) completed successfully. \n ---%v--- \n%s\n ------", pod.Name, containerName, args, stdout.String())
	return stdout.String(), nil
}

func (n k8snode) Drain(k8sClientset *kubernetes.Clientset) error {
	nodeName := string(n)
	log.Infof("Start drain node %s", nodeName)

	helper := newDrainHelper(k8sClientset)
	if err := cordonNode(k8sClientset, nodeName, true); err != nil {
		return fmt.Errorf("failed to cordon node %s: %w", nodeName, err)
	}

	list, errs := helper.GetPodsForDeletion(nodeName)
	if len(errs) > 0 {
		return fmt.Errorf("failed to list pods for drain on node %s: %w", nodeName, errors.Join(errs...))
	}
	if warnings := list.Warnings(); warnings != "" {
		log.Warnf("Drain warnings for node %s: %s", nodeName, warnings)
	}
	if err := helper.DeleteOrEvictPods(list.Pods()); err != nil {
		return fmt.Errorf("failed to drain node %s: %w", nodeName, err)
	}

	log.Infof("Drain node %s completed successfully.", nodeName)
	return nil
}

func (n k8snode) Uncordon(k8sClientset *kubernetes.Clientset) error {
	nodeName := string(n)
	log.Infof("Start uncordon node %s", nodeName)
	if err := cordonNode(k8sClientset, nodeName, false); err != nil {
		return fmt.Errorf("failed to uncordon node %s: %w", nodeName, err)
	}
	log.Infof("Uncordon node %s completed successfully.", nodeName)
	return nil
}

// newDrainHelper returns a kubectl drain.Helper configured with the same
// semantics as `kubectl drain --ignore-daemonsets --delete-emptydir-data --force`.
func newDrainHelper(k8sClientset *kubernetes.Clientset) *drain.Helper {
	return &drain.Helper{
		Ctx:                 context.Background(),
		Client:              k8sClientset,
		Force:               true,
		IgnoreAllDaemonSets: true,
		DeleteEmptyDirData:  true,
		GracePeriodSeconds:  -1,
		Out:                 log.StandardLogger().WriterLevel(log.InfoLevel),
		ErrOut:              log.StandardLogger().WriterLevel(log.WarnLevel),
	}
}

// cordonNode sets the node's Unschedulable flag to the desired value using
// kubectl's CordonHelper, which patches only when an update is required.
func cordonNode(k8sClientset *kubernetes.Clientset, nodeName string, desired bool) error {
	node, err := k8sClientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	cordonHelper := drain.NewCordonHelper(node)
	if !cordonHelper.UpdateIfRequired(desired) {
		return nil
	}
	if err, patchErr := cordonHelper.PatchOrReplaceWithContext(context.Background(), k8sClientset, false); err != nil || patchErr != nil {
		if err != nil {
			return err
		}
		return patchErr
	}
	return nil
}

func removeLabelForAllNodes(k8sClientset *kubernetes.Clientset, key string) error {
	log.Infof("Start remove node label %s", key)

	nodes, err := k8sClientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	// Escape the label key per RFC 6901 so it can be used in a JSON Patch path.
	escaped := strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
	patch := []byte(fmt.Sprintf(`[{"op":"remove","path":"/metadata/labels/%s"}]`, escaped))

	for _, node := range nodes.Items {
		if _, ok := node.Labels[key]; !ok {
			continue
		}
		if _, err := k8sClientset.CoreV1().Nodes().Patch(context.Background(), node.Name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
			return fmt.Errorf("failed to remove label %s from node %s: %w", key, node.Name, err)
		}
	}

	log.Infof("Remove node label %s completed successfully.", key)
	return nil
}

// Get value of a node label.
// If node does not have that label, return empty string and error.
func getNodeLabelValue(node *v1.Node, key string) (string, error) {
	currentVal, ok := node.Labels[key]
	if !ok {
		return "", fmt.Errorf("node label (%s) does not exists", key)
	}

	return currentVal, nil
}

// Update a value in ConfigMap.
func updateConfigMapValue(k8sClientset *kubernetes.Clientset, namespace, name, key, value string) error {
	configMap, err := k8sClientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if currentVal, ok := configMap.Data[key]; ok && currentVal == value {
		log.Infof("Config map %s has %s=%s already. No update needed.", name, key, value)
		return nil
	}
	configMap.Data[key] = value

	_, err = k8sClientset.CoreV1().ConfigMaps(namespace).Update(context.Background(), configMap, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	log.Infof("Config map %s updated %s=%s.", name, key, value)
	return nil
}

// wait for a node label to disappear.
// This is a function for testing purpose.
func (n k8snode) waitForNodeLabelDisappear(k8sClientset *kubernetes.Clientset, key string, interval, timeout time.Duration) error {
	nodeName := string(n)
	log.Infof("Waiting for node %s label %s to disappear.", nodeName, key)

	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, true, func(ctx context.Context) (bool, error) {
		node, err := k8sClientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			// Cannot get node, something wrong, stop waiting.
			return true, err
		}

		if _, ok := node.Labels[key]; !ok {
			// Node label gone, stop waiting.
			return true, nil
		}

		// retry.
		return false, nil
	})
}

// Return true if a node does not exist in the cluster.
func (n k8snode) CheckNotExists(k8sClientset *kubernetes.Clientset) (bool, error) {
	nodeName := string(n)
	_, err := k8sClientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if apierrs.IsNotFound(err) {
		return true, nil
	}

	return false, err
}
