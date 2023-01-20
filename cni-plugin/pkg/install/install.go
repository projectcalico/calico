// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package install

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kelseyhightower/envconfig"
	"github.com/nmrshll/go-cp"
	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/client/pkg/v3/fileutil"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/libcalico-go/lib/seedrng"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/node/pkg/cni"
)

type config struct {
	// Location on the host where CNI network configs are stored.
	CNINetDir   string `envconfig:"CNI_NET_DIR" default:"/etc/cni/net.d"`
	CNIConfName string `envconfig:"CNI_CONF_NAME"`

	// Directory where we expect that TLS assets will be mounted into the calico/cni container.
	TLSAssetsDir string `envconfig:"TLS_ASSETS_DIR" default:"/calico-secrets"`

	// SkipCNIBinaries is a comma-separated list of binaries. Each binary in the list
	// will be skipped when installing to the host.
	SkipCNIBinaries []string `envconfig:"SKIP_CNI_BINARIES"`

	// UpdateCNIBinaries controls whether or not to overwrite any binaries with the same name
	// on the host.
	UpdateCNIBinaries bool `envconfig:"UPDATE_CNI_BINARIES" default:"true"`

	// The CNI network configuration to install.
	CNINetworkConfig     string `envconfig:"CNI_NETWORK_CONFIG"`
	CNINetworkConfigFile string `envconfig:"CNI_NETWORK_CONFIG_FILE"`

	ShouldSleep bool `envconfig:"SLEEP" default:"true"`

	ServiceAccountToken []byte
}

func (c config) skipBinary(binary string) bool {
	for _, name := range c.SkipCNIBinaries {
		if name == binary {
			return true
		}
	}
	return false
}

func getEnv(env, def string) string {
	if val, ok := os.LookupEnv(env); ok {
		return val
	}
	return def
}

func directoryExists(dir string) bool {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		logrus.WithError(err).Fatalf("Failed to check if directory %s exists", dir)
		return false
	}
	return info.IsDir()
}

func fileExists(file string) bool {
	info, err := os.Stat(file)
	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		logrus.WithError(err).Fatalf("Failed to check if file %s exists", file)
		return false
	}
	return !info.IsDir()
}

func mkdir(path string) {
	if err := os.MkdirAll(path, 0777); err != nil {
		logrus.WithError(err).Fatalf("Failed to create directory %s", path)
	}
}

func loadConfig() config {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		logrus.Fatal(err.Error())
	}

	return c
}

// getServiceAccountFilePaths returns the mount paths for a container
// In the case of Windows HostProcess containers this prepends the CONTAINER_SANDBOX_MOUNT_POINT env variable
// for other operating systems or if the sandbox env variable is not set it returns the standard mount points
// see https://kubernetes.io/docs/tasks/configure-pod-container/create-hostprocess-pod/#volume-mounts
func getHostPath(path string) string {
	if runtime.GOOS == "windows" {
		sandbox := os.Getenv("CONTAINER_SANDBOX_MOUNT_POINT")
		// join them and return with forward slashes so it can be serialized properly in json later if required
		path := filepath.Join(sandbox, path)
		return filepath.ToSlash(path)
	}
	return path
}

func Install() error {
	// Make sure the RNG is seeded.
	seedrng.EnsureSeeded()

	// Configure logging before anything else.
	logrus.SetFormatter(&logutils.Formatter{Component: "cni-installer"})

	// Clean up any existing binaries / config / assets.
	if err := os.RemoveAll(getHostPath("/host/etc/cni/net.d/calico-tls")); err != nil && !os.IsNotExist(err) {
		logrus.WithError(err).Warnf("Error removing old TLS directory")
	}

	// Load config.
	c := loadConfig()

	// Determine if we're running as a Kubernetes pod.
	var kubecfg *rest.Config

	serviceAccountTokenFile := getHostPath("/var/run/secrets/kubernetes.io/serviceaccount/token")
	c.ServiceAccountToken = make([]byte, 0)
	var err error
	if fileExists(serviceAccountTokenFile) {
		log.Info("Running as a Kubernetes pod")
		kubecfg, err = rest.InClusterConfig()
		if err != nil {
			return err
		}
		err = rest.LoadTLSFiles(kubecfg)
		if err != nil {
			return err
		}

		c.ServiceAccountToken, err = os.ReadFile(serviceAccountTokenFile)
		if err != nil {
			return err
		}
	}

	// Copy over any TLS assets from the SECRETS_MOUNT_DIR to the host.
	// First check if the dir exists and has anything in it.
	if directoryExists(c.TLSAssetsDir) {
		logrus.Info("Installing any TLS assets")
		mkdir("/host/etc/cni/net.d/calico-tls")
		if err := copyFileAndPermissions(fmt.Sprintf("%s/%s", c.TLSAssetsDir, "etcd-ca"), getHostPath("/host/etc/cni/net.d/calico-tls/etcd-ca")); err != nil {
			logrus.Warnf("Missing etcd-ca")
		}
		if err := copyFileAndPermissions(fmt.Sprintf("%s/%s", c.TLSAssetsDir, "etcd-cert"), getHostPath("/host/etc/cni/net.d/calico-tls/etcd-cert")); err != nil {
			logrus.Warnf("Missing etcd-cert")
		}
		if err := copyFileAndPermissions(fmt.Sprintf("%s/%s", c.TLSAssetsDir, "etcd-key"), getHostPath("/host/etc/cni/net.d/calico-tls/etcd-key")); err != nil {
			logrus.Warnf("Missing etcd-key")
		}
	}

	// Set the suid bit on the binaries to allow them to run as non-root users.
	if err := setSuidBit(getHostPath("/opt/cni/bin/install")); err != nil {
		logrus.WithError(err).Fatalf("Failed to set the suid bit on the install binary")
	}

	// TODO: Remove the setSUID code here on calico and calico-ipam when they eventually
	// get refactored to all use install as the source.
	if err := setSuidBit(getHostPath("/opt/cni/bin/calico")); err != nil {
		logrus.WithError(err).Fatalf("Failed to set the suid bit on the calico binary")
	}

	if err := setSuidBit(getHostPath("/opt/cni/bin/calico-ipam")); err != nil {
		logrus.WithError(err).Fatalf("Failed to set the suid bit on the calico-ipam")
	}

	// Place the new binaries if the directory is writeable.
	dirs := []string{getHostPath("/host/opt/cni/bin"), getHostPath("/host/secondary-bin-dir")}
	binsWritten := false
	for _, d := range dirs {
		if err := fileutil.IsDirWriteable(d); err != nil {
			logrus.Infof("%s is not writeable, skipping", d)
			continue
		}

		// Iterate through each binary we might want to install.
		files, err := ioutil.ReadDir(getHostPath("/opt/cni/bin/"))
		if err != nil {
			log.Fatal(err)
		}
		for _, binary := range files {
			target := fmt.Sprintf("%s/%s", d, binary.Name())
			source := getHostPath(fmt.Sprintf("/opt/cni/bin/%s", binary.Name()))
			if c.skipBinary(binary.Name()) {
				continue
			}
			if fileExists(target) && !c.UpdateCNIBinaries {
				logrus.Infof("Skipping installation of %s", target)
				continue
			}
			if err := copyFileAndPermissions(source, target); err != nil {
				logrus.WithError(err).Errorf("Failed to install %s", target)
				os.Exit(1)
			}
			logrus.Infof("Installed %s", target)
		}

		// Binaries were placed into at least one directory
		logrus.Infof("Wrote Calico CNI binaries to %s\n", d)
		binsWritten = true

		// Print CNI plugin version to confirm that the binary was actually written.
		// If this fails, it means something has gone wrong so we should retry.
		cmd := exec.Command(d+"/calico", "-v")
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			logrus.WithError(err).Warnf("Failed getting CNI plugin version from installed binary, exiting")
			return err
		}
		logrus.Infof("CNI plugin version: %s", out.String())
	}

	// If binaries were not placed, exit
	if !binsWritten {
		logrus.WithError(err).Fatalf("found no writeable directory, exiting")
	}

	if kubecfg != nil {
		// If running as a Kubernetes pod, then write out a kubeconfig for the
		// CNI plugin to use.
		writeKubeconfig(kubecfg)
	}

	// Write a CNI config file.
	writeCNIConfig(c)

	// Unless told otherwise, sleep forever.
	// This prevents Kubernetes from restarting the pod repeatedly.
	logrus.Infof("Done configuring CNI.  Sleep= %v", c.ShouldSleep)
	for c.ShouldSleep {
		// Kubernetes Secrets can be updated.  If so, we need to install the updated
		// version to the host. Just check the timestamp on the certificate to see if it
		// has been updated.  A bit hokey, but likely good enough.
		filename := c.TLSAssetsDir + "/etcd-cert"

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}

		done := make(chan bool)

		// Process events
		go func() {
			for {
				select {
				case <-watcher.Events:
					logrus.Infoln("Updating installed secrets at:", time.Now().String())
					files, err := os.ReadDir(c.TLSAssetsDir)
					if err != nil {
						logrus.Warn(err)
					}
					for _, f := range files {
						if err = copyFileAndPermissions(c.TLSAssetsDir+"/"+f.Name(), "/host/etc/cni/net.d/calico-tls/"+f.Name()); err != nil {
							logrus.Warn(err)
							continue
						}
					}
				case err := <-watcher.Errors:
					log.Fatal(err)
				}
			}
		}()

		err = watcher.Add(filename)
		if err != nil {
			log.Fatal(err)
		}

		<-done

		watcher.Close()
	}
	return nil
}

func isValidJSON(s string) error {
	var js map[string]interface{}
	return json.Unmarshal([]byte(s), &js)
}

func writeCNIConfig(c config) {
	netconf := defaultNetConf()

	// Pick the config template to use. This can either be through an env var,
	// or a file mounted into the container.
	if c.CNINetworkConfig != "" {
		log.Info("Using CNI config template from CNI_NETWORK_CONFIG environment variable.")
		netconf = c.CNINetworkConfig
	}
	if c.CNINetworkConfigFile != "" {
		log.Info("Using CNI config template from CNI_NETWORK_CONFIG_FILE")
		var err error
		netconfBytes, err := os.ReadFile(c.CNINetworkConfigFile)
		if err != nil {
			log.Fatal(err)
		}
		netconf = string(netconfBytes)
	}

	kubeconfigPath := c.CNINetDir + "/calico-kubeconfig"

	// Perform replacements of variables.
	nodename, err := names.Hostname()
	if err != nil {
		log.Fatal(err)
	}
	netconf = strings.Replace(netconf, "__LOG_LEVEL__", getEnv("LOG_LEVEL", "info"), -1)
	netconf = strings.Replace(netconf, "__LOG_FILE_PATH__", getEnv("LOG_FILE_PATH", "/var/log/calico/cni/cni.log"), -1)
	netconf = strings.Replace(netconf, "__LOG_FILE_MAX_SIZE__", getEnv("LOG_FILE_MAX_SIZE", "100"), -1)
	netconf = strings.Replace(netconf, "__LOG_FILE_MAX_AGE__", getEnv("LOG_FILE_MAX_AGE", "30"), -1)
	netconf = strings.Replace(netconf, "__LOG_FILE_MAX_COUNT__", getEnv("LOG_FILE_MAX_COUNT", "10"), -1)
	netconf = strings.Replace(netconf, "__DATASTORE_TYPE__", getEnv("DATASTORE_TYPE", "kubernetes"), -1)
	netconf = strings.Replace(netconf, "__KUBERNETES_NODE_NAME__", getEnv("KUBERNETES_NODE_NAME", nodename), -1)
	netconf = strings.Replace(netconf, "__KUBECONFIG_FILEPATH__", kubeconfigPath, -1)
	netconf = strings.Replace(netconf, "__CNI_MTU__", getEnv("CNI_MTU", "1500"), -1)

	netconf = strings.Replace(netconf, "__KUBERNETES_SERVICE_HOST__", getEnv("KUBERNETES_SERVICE_HOST", ""), -1)
	netconf = strings.Replace(netconf, "__KUBERNETES_SERVICE_PORT__", getEnv("KUBERNETES_SERVICE_PORT", ""), -1)

	netconf = strings.Replace(netconf, "__SERVICEACCOUNT_TOKEN__", string(c.ServiceAccountToken), -1)

	// Perform replacement of windows variables
	if runtime.GOOS == "windows" {
		netconf = strings.Replace(netconf, "__ROUTE_TYPE__", getEnv("ROUTE_TYPE", "OutBoundNAT"), -1)
		netconf = strings.Replace(netconf, "__K8S_SERVICE_CIDR__", getEnv("K8S_SERVICE_CIDR", "10.96.0.0/12"), -1)
		netconf = strings.Replace(netconf, "__VNI__", getEnv("VXLAN_VNI", "4096"), -1)
		netconf = strings.Replace(netconf, "__MAC_PREFIX__", getEnv("MAC_PREFIX", "0E-2A"), -1)
		netconf = strings.Replace(netconf, "__VNI__", getEnv("VXLAN_VNI", "4096"), -1)
	}

	// Replace etcd datastore variables.
	hostSecretsDir := c.CNINetDir + "/calico-tls"
	if fileExists(getHostPath("/host/etc/cni/net.d/calico-tls/etcd-cert")) {
		etcdCertFile := fmt.Sprintf("%s/etcd-cert", hostSecretsDir)
		netconf = strings.Replace(netconf, "__ETCD_CERT_FILE__", etcdCertFile, -1)
	} else {
		netconf = strings.Replace(netconf, "__ETCD_CERT_FILE__", "", -1)
	}

	if fileExists(getHostPath("/host/etc/cni/net.d/calico-tls/etcd-ca")) {
		etcdCACertFile := fmt.Sprintf("%s/etcd-ca", hostSecretsDir)
		netconf = strings.Replace(netconf, "__ETCD_CA_CERT_FILE__", etcdCACertFile, -1)
	} else {
		netconf = strings.Replace(netconf, "__ETCD_CA_CERT_FILE__", "", -1)
	}

	if fileExists(getHostPath("/host/etc/cni/net.d/calico-tls/etcd-key")) {
		etcdKeyFile := fmt.Sprintf("%s/etcd-key", hostSecretsDir)
		netconf = strings.Replace(netconf, "__ETCD_KEY_FILE__", etcdKeyFile, -1)
	} else {
		netconf = strings.Replace(netconf, "__ETCD_KEY_FILE__", "", -1)
	}
	netconf = strings.Replace(netconf, "__ETCD_ENDPOINTS__", getEnv("ETCD_ENDPOINTS", ""), -1)
	netconf = strings.Replace(netconf, "__ETCD_DISCOVERY_SRV__", getEnv("ETCD_DISCOVERY_SRV", ""), -1)

	err = isValidJSON(netconf)
	if err != nil {
		log.Fatalf("%s is not a valid json object\nerror: %s", netconf, err)
	}

	// Write out the file.
	name := getEnv("CNI_CONF_NAME", "10-calico.conflist")
	path := getHostPath(fmt.Sprintf("/host/etc/cni/net.d/%s", name))
	err = ioutil.WriteFile(path, []byte(netconf), 0644)
	if err != nil {
		log.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	logrus.Infof("Created /host/etc/cni/net.d/%s", name)
	text := string(content)
	fmt.Println(text)

	// Remove any old config file, if one exists.
	oldName := getEnv("CNI_OLD_CONF_NAME", "10-calico.conflist")
	if name != oldName {
		logrus.Infof("Removing /host/etc/cni/net.d/%s", oldName)
		if err := os.Remove(getHostPath(fmt.Sprintf("/host/etc/cni/net.d/%s", oldName))); err != nil {
			logrus.WithError(err).Warnf("Failed to remove %s", oldName)
		}
	}
}

// copyFileAndPermissions copies file permission
func copyFileAndPermissions(src, dst string) (err error) {
	// If the source and destination are the same, we can simply return.
	skip, err := destinationUptoDate(src, dst)
	if err != nil {
		return err
	}
	if skip {
		logrus.WithField("file", dst).Info("File is already up to date, skipping")
		return nil
	}

	// Make a temporary file at the destination.
	dstTmp := fmt.Sprintf("%s.tmp", dst)
	if err := cp.CopyFile(src, dstTmp); err != nil {
		return fmt.Errorf("failed to copy file: %s", err)
	}

	// Move the temporary file into position. Using Rename is atomic
	// (i.e., mv) and avoids issues where the destination file is in use.
	err = os.Rename(dstTmp, dst)
	if err != nil {
		return fmt.Errorf("failed to rename file: %s", err)
	}

	if runtime.GOOS == "windows" {
		// chmod doesn't work on windows
		return
	}

	// chmod the dst file to match the original permissions.
	si, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat file: %s", err)
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		return fmt.Errorf("failed to chmod file: %s", err)
	}

	return
}

func writeKubeconfig(kubecfg *rest.Config) {
	data := `# Kubeconfig file for Calico CNI plugin.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: __KUBERNETES_SERVICE_PROTOCOL__://[__KUBERNETES_SERVICE_HOST__]:__KUBERNETES_SERVICE_PORT__
    __TLS_CFG__
users:
- name: calico
  user:
    token: TOKEN
contexts:
- name: calico-context
  context:
    cluster: local
    user: calico
current-context: calico-context`

	clientset, err := cni.BuildClientSet()
	if err != nil {
		logrus.WithError(err).Fatal("Unable to create client for generating CNI token")
	}
	tr := cni.NewTokenRefresher(clientset, cni.NamespaceOfUsedServiceAccount(), cni.CNIServiceAccountName())
	tu, err := tr.UpdateToken()
	if err != nil {
		logrus.WithError(err).Fatal("Unable to create token for CNI kubeconfig")
	}
	data = strings.Replace(data, "TOKEN", tu.Token, 1)
	data = strings.Replace(data, "__KUBERNETES_SERVICE_PROTOCOL__", getEnv("KUBERNETES_SERVICE_PROTOCOL", "https"), -1)
	data = strings.Replace(data, "__KUBERNETES_SERVICE_HOST__", getEnv("KUBERNETES_SERVICE_HOST", ""), -1)
	data = strings.Replace(data, "__KUBERNETES_SERVICE_PORT__", getEnv("KUBERNETES_SERVICE_PORT", ""), -1)

	skipTLSVerify := os.Getenv("SKIP_TLS_VERIFY")
	if skipTLSVerify == "true" {
		data = strings.Replace(data, "__TLS_CFG__", "insecure-skip-tls-verify: true", -1)
	} else {
		ca := "certificate-authority-data: " + base64.StdEncoding.EncodeToString(kubecfg.CAData)
		data = strings.Replace(data, "__TLS_CFG__", ca, -1)
	}

	if err := ioutil.WriteFile(getHostPath("/host/etc/cni/net.d/calico-kubeconfig"), []byte(data), 0600); err != nil {
		log.Fatal(err)
	}
}

func setSuidBit(file string) error {
	fi, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("failed to stat file: %s", err)
	}
	err = os.Chmod(file, fi.Mode()|os.FileMode(uint32(8388608)))
	if err != nil {
		return fmt.Errorf("failed to chmod file: %s", err)
	}

	return nil
}

// destinationUptoDate compares the given files and returns
// whether or not the destination file needs to be updated with the
// contents of the source file.
func destinationUptoDate(src, dst string) (bool, error) {
	// Stat the src file.
	f1info, err := os.Stat(src)
	if os.IsNotExist(err) {
		// If the source file doesn't exist, that's an unrecoverable problem.
		return false, err
	} else if err != nil {
		return false, err
	}

	// Stat the dst file.
	f2info, err := os.Stat(dst)
	if os.IsNotExist(err) {
		// If the destination file doesn't exist, it means the
		// two files are not equal.
		return false, nil
	} else if err != nil {
		return false, err
	}

	// First, compare the files sizes and modes. No point in comparing
	// file contents if they differ in size or file mode.
	if f1info.Size() != f2info.Size() {
		return false, nil
	}
	if f1info.Mode() != f2info.Mode() {
		return false, nil
	}

	// Files have the same exact size and mode, check the actual contents.
	f1, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer f1.Close()

	f2, err := os.Open(dst)
	if err != nil {
		log.Fatal(err)
	}
	defer f2.Close()

	// Create a buffer, which we'll use to read both files.
	buf := make([]byte, 64000)

	// Iterate the files until we reach the end. If we spot a difference,
	// we know that the files are not the same. Otherwise, if we reach the
	// end of the file before seeing a difference, the files are identical.
	for {

		// Read the two files.
		bytesRead, err1 := f1.Read(buf)
		s1 := string(buf[:bytesRead])
		bytesRead2, err2 := f2.Read(buf)
		s2 := string(buf[:bytesRead2])

		if err1 != nil || err2 != nil {
			if err1 == io.EOF && err2 == io.EOF {
				// Reached the end of both files.
				return true, nil
			} else if err1 == io.EOF || err2 == io.EOF {
				// Reached the end of one file, but not the other. They are different.
				return false, nil
			} else if err1 != nil {
				// Other error - return it.
				return false, err1
			} else if err2 != nil {
				// Other error - return it.
				return false, err2
			}
		} else if bytesRead != bytesRead2 {
			// Read a different number of bytes from each file. Defensively
			// consider the files different.
			return false, nil
		}

		if s1 != s2 {
			// The slice of bytes we read from each file are not equal.
			return false, nil
		}

		// The slice of bytes we read from each file are equal. Loop again, checking the next
		// slice of bytes.
	}
}
