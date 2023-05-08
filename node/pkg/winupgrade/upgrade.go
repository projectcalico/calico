// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package winupgrade

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	image "github.com/distribution/distribution/reference"

	"github.com/projectcalico/calico/node/pkg/lifecycle/startup"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"

	log "github.com/sirupsen/logrus"
)

const (
	CalicoKubeConfigFile    = "calico-kube-config"
	CalicoUpgradeDir        = "c:\\CalicoUpgrade"
	EnterpriseDir           = "TigeraCalico"
	CalicoUpgradeLabel      = "projectcalico.org/windows-upgrade"
	CalicoUpgradeInProgress = "in-progress"
	CalicoVersionAnnotation = "projectcalico.org/version"
	CalicoVariantAnnotation = "projectcalico.org/variant"
	CalicoUpgradeScript     = "calico-upgrade.ps1"
)

func getVariant() string {
	if runningEnterprise() {
		return "TigeraSecureEnterprise"
	}
	return "Calico"
}

func getVersion() string {
	return startup.VERSION
}

// This file contains the upgrade processing for the calico/node.  This
// includes:
// - Monitoring node labels and getting the Calico Windows upgrade script file from the label.
// - Uninstalling current Calico Windows (OSS or Enterprise) running on the node.
// - Install new version of Calico Windows.
func Run() {
	version := getVersion()
	variant := getVariant()

	// Determine the name for this node.
	nodeName := utils.DetermineNodeName()
	log.Infof("Starting Calico upgrade service on node: %s. Version: %s, Variant: %s, baseDir: %s", nodeName, version, variant, baseDir())

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile())
	if err != nil {
		log.WithError(err).Fatal("Failed to build Kubernetes client config")
	}
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.WithError(err).Fatal("Failed to create Kubernetes client")
	}

	stdout, stderr, err := powershell("Get-ComputerInfo | select WindowsVersion, OsBuildNumber, OsHardwareAbstractionLayer")
	fmt.Println(stdout, stderr)
	if err != nil {
		log.WithError(err).Fatal("Failed to interact with powershell")
	}

	ctx, cancel := context.WithCancel(context.Background())
	go loop(ctx, clientSet, nodeName)

	// Trap cancellation on Windows. https://golang.org/pkg/os/signal/
	sigCh := make(chan os.Signal, 1)
	signal.Notify(
		sigCh,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
	)

	<-sigCh
	cancel()
	log.Info("Received system signal to exit")
}

func loop(ctx context.Context, cs kubernetes.Interface, nodeName string) {
	ticker := time.NewTicker(10 * time.Second)
	upgradeScript := filepath.Join(CalicoUpgradeDir, CalicoUpgradeScript)

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			upgrade, err := upgradeTriggered(ctx, cs, nodeName)
			if err != nil {
				log.WithError(err).Error("Failed to check node upgrade status, will retry")
				break
			}
			// If upgrade not triggered yet just silently continue.
			if !upgrade {
				break
			}

			if !pathExists(upgradeScript) {
				log.Info("Upgrade triggered but upgrade artifacts not ready yet, will retry")
				break
			}

			log.Info("Calico upgrade process is starting")

			// Before executing the script, verify host path volume mount.
			err = verifyPodImageWithHostPathVolume(cs, nodeName, CalicoUpgradeDir)
			if err != nil {
				log.WithError(err).Fatal("Failed to verify windows-upgrade pod image")
			}

			err = uninstall()
			if err != nil {
				log.WithError(err).Error("Uninstall failed, will retry")
				break
			}

			time.Sleep(3 * time.Second)
			err = execScript(upgradeScript)
			if err != nil {
				log.WithError(err).Fatal("Failed to upgrade to new version")
			}

			// Upgrade will run in another process. The running
			// calico-upgrade service is done. The new calico-upgrade
			// service will clean the old service up.
			date := time.Now().Format("2006-01-02")
			log.Info(fmt.Sprintf("Upgrade is in progress. Upgrade log is in c:\\calico-upgrade.%v.log", date))
			time.Sleep(3 * time.Second)
			return
		}
	}
}

func upgradeTriggered(ctx context.Context, cs kubernetes.Interface, nodeName string) (bool, error) {
	node, err := cs.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	// Return error getting node info.
	if err != nil {
		return false, fmt.Errorf("Could not get node resource: %w", err)
	}

	upgradeStatus, ok := node.Labels[CalicoUpgradeLabel]
	// Upgrade label doesn't exist yet.
	if !ok {
		return false, nil
	}
	if upgradeStatus != CalicoUpgradeInProgress {
		return false, fmt.Errorf("Unexpected upgrade status label value: %v", upgradeStatus)
	}

	return true, nil
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}

	return true
}

// Return the base directory for Calico upgrade service.
func baseDir() string {
	dir := filepath.Dir(os.Args[0])
	return "c:\\" + filepath.Base(dir)
}

// Return if the monitor service is running as part of Enterprise installation.
func runningEnterprise() bool {
	return strings.Contains(baseDir(), EnterpriseDir)
}

// Return kubeconfig file path for Calico
func kubeConfigFile() string {
	return baseDir() + "\\" + CalicoKubeConfigFile
}

func uninstall() error {
	path := filepath.Join(baseDir(), "uninstall-calico.ps1")
	log.Infof("Start uninstall script %s\n", path)
	stdout, stderr, err := powershell(path + " -ExceptUpgradeService $true")
	fmt.Println(stdout, stderr)
	if err != nil {
		return err
	}
	// After the uninstall completes, move the existing calico-node.exe to
	// a temporary file. The calico-upgrade service is still running so not
	// doing this means we cannot replace calico-node.exe with the upgrade.
	stdout, stderr, err = powershell(fmt.Sprintf(`mv %v\calico-node.exe %v\calico-node.exe.to-be-replaced`, baseDir(), baseDir()))
	fmt.Println(stdout, stderr)
	if err != nil {
		return err
	}

	return nil
}

func execScript(script string) error {
	log.Infof("Start script %s\n", script)

	// This has to be done in a separate process because when the new calico services are started, the existing
	// calico-upgrade service is removed so the new calico-upgrade service can be started.
	// However, removing the existing calico-upgrade service means the powershell
	// process running the upgrade script is killed and the installation is left
	// incomplete.
	cmd := fmt.Sprintf(`Start-Process powershell -argument %q -WindowStyle hidden`, script)
	stdout, stderr, err := powershell(cmd)

	if err != nil {
		return err
	}
	fmt.Println(stdout, stderr)
	return nil
}

func verifyImagesSharePathPrefix(first, second string) error {
	n1, err := image.ParseNamed(first)
	if err != nil {
		return err
	}
	n2, err := image.ParseNamed(second)
	if err != nil {
		return err
	}
	// Compare the domain parts (e.g. docker.io) of the image references.
	// Domain is always present, ParseNamed fails without a domain.
	if image.Domain(n1) != image.Domain(n2) {
		return fmt.Errorf("images %q and %q do not share the same domain", first, second)
	}

	// Split the image path. E.g. if the image is
	// "docker.io/calico/node:v3.21.0" then the path is "calico/node".
	n1PathParts := strings.Split(image.Path(n1), "/")
	n2PathParts := strings.Split(image.Path(n2), "/")

	// Special case: if the image references are both short image references
	// like my-registry.org/node:v3.21.0 then the path will just be the image
	// component itself. In this case, we can only compare the domain.
	if len(n1PathParts) == 1 && len(n2PathParts) == 1 {
		return nil
	}

	// Validation should catch this but just in case.
	if len(n1PathParts) == 0 || len(n2PathParts) == 0 {
		return fmt.Errorf("images %q and/or %q do not contain a valid path", first, second)
	}

	// If image paths do not have equal # of segments then they don't match.
	if len(n1PathParts) != len(n2PathParts) {
		return fmt.Errorf("images %q and %q do not share the same path prefix", first, second)
	}

	// Remove the last segment of the image path since it will contain the
	// component name.
	n1PathPrefix := n1PathParts[:len(n1PathParts)-1]
	n2PathPrefix := n2PathParts[:len(n2PathParts)-1]

	// Compare the image path prefix (e.g. "docker.io/calico", "quay.io/calico")
	// of the two images
	for i := range n1PathPrefix {
		if n1PathPrefix[i] != n2PathPrefix[i] {
			return fmt.Errorf("images %q and %q are not from the same registry and path", first, second)
		}
	}
	return nil
}

func verifyPodImageWithHostPathVolume(cs kubernetes.Interface, nodeName string, hostPath string) error {
	// Get pod list for calico-system pods.
	list, err := cs.CoreV1().Pods("calico-system").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	// Find the calico-node pod.
	var calicoPod v1.Pod
	var found bool
	for _, pod := range list.Items {
		if strings.HasPrefix(pod.Name, "calico-node") && pod.Spec.ServiceAccountName == "calico-node" {
			calicoPod = pod
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("could not find a calico-node pod")
	}

	// Ensure the pod is owned by the calico-node daemonset.
	var ownedByCalicoDs bool
	for _, ownerRef := range calicoPod.ObjectMeta.OwnerReferences {
		if ownerRef.Kind == "DaemonSet" && ownerRef.Name == "calico-node" && *ownerRef.Controller {
			ownedByCalicoDs = true
		}
	}
	if !ownedByCalicoDs {
		return fmt.Errorf("calico-node pod not owned by calico-node daemonset")
	}

	// Get the calico node nodeImage
	var nodeImage string
	for _, c := range calicoPod.Spec.Containers {
		if c.Name == "calico-node" {
			nodeImage = c.Image
			break
		}
	}
	if nodeImage == "" {
		return fmt.Errorf("calico-node container image not found")
	}

	log.Infof("Found node container image is %v", nodeImage)

	hasHostPathVolume := func(pod v1.Pod, hostPath string) bool {
		for _, v := range pod.Spec.Volumes {
			path := v.HostPath
			if path == nil {
				continue
			}
			if path.Path == hostPath {
				return true
			}
		}
		return false
	}

	var podWithHostPath v1.Pod
	count := 0
	for _, pod := range list.Items {
		// Only look at pods on this node.
		if pod.Spec.NodeName != nodeName {
			continue
		}
		if hasHostPathVolume(pod, hostPath) {
			podWithHostPath = pod
			count++
		}
	}

	if count == 0 {
		return fmt.Errorf("Failed to find pod with expected host path")
	}

	if count > 1 {
		return fmt.Errorf("More than one pod has expected host path")
	}

	if len(podWithHostPath.Spec.Containers) != 1 {
		return fmt.Errorf("Pod with hostpath volume has more than one container")
	}
	upgradeImage := podWithHostPath.Spec.Containers[0].Image
	log.Infof("Found upgrade image: %v", upgradeImage)
	err = verifyImagesSharePathPrefix(nodeImage, upgradeImage)
	if err != nil {
		return err
	}
	return nil
}

func powershell(args ...string) (string, string, error) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", "", err
	}

	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(ps, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return "", "", err
	}

	return stdout.String(), stderr.String(), err
}
