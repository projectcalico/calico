//  Copyright (c) 2020 Tigera, Inc. All rights reserved.
package install

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"
)

var expectedDefaultConfig string = `{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "log_level": "info",
      "log_file_path": "/var/log/calico/cni/cni.log",
      "datastore_type": "kubernetes",
      "nodename": "my-node",
      "mtu": 1500,
      "ipam": {"type": "calico-ipam"},
      "policy": {"type": "k8s"},
      "kubernetes": {"kubeconfig": "/etc/cni/net.d/calico-kubeconfig"}
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    }
  ]
}`

var expectedAlternateConfig string = `{
    "name": "alternate",
    "type": "calico",
    "etcd_endpoints": "",
    "etcd_discovery_srv": "",
    "etcd_key_file": "",
    "etcd_cert_file": "",
    "etcd_ca_cert_file": "",
    "log_level": "info",
    "ipam": {
        "type": "calico-ipam"
    },
    "policy": {
        "type": "k8s",
        "k8s_api_root": "https://127.0.0.1:6443",
        "k8s_auth_token": "my-secret-key"
    },
    "kubernetes": {
        "kubeconfig": "/etc/cni/net.d/calico-kubeconfig"
    }
}`

// runCniContainer will run the install binary within the CNI container.
func runCniContainer(tempDir string, binFolderWriteable bool, extraArgs ...string) error {
	name := "cni"

	// Ensure the install cni container was not left over from another run.
	out, err := exec.Command("docker", "rm", name).CombinedOutput()
	if err != nil {
		if !strings.Contains(string(out), "No such container: "+name) {
			Fail(fmt.Sprintf("Error running docker command: %s", out))
		}
	}

	// Assemble our arguments.
	binFolder := "/host/opt/cni/bin"
	if !binFolderWriteable {
		binFolder += ":ro"
	}
	args := []string{
		"run", "--rm", "--name", name,
		"-e", "SLEEP=false",
		"-e", "KUBERNETES_SERVICE_HOST=127.0.0.1",
		"-e", "KUBERNETES_SERVICE_PORT=6443",
		"-e", "KUBERNETES_NODE_NAME=my-node",
		"-v", tempDir + "/bin:" + binFolder,
		"-v", tempDir + "/net.d:/host/etc/cni/net.d",
		"-v", tempDir + "/serviceaccount:/var/run/secrets/kubernetes.io/serviceaccount",
	}
	args = append(args, extraArgs...)
	image := os.Getenv("CONTAINER_NAME")
	args = append(args, image, "/opt/cni/bin/install")

	out, err = exec.Command("docker", args...).CombinedOutput()
	_, writeErr := GinkgoWriter.Write(out)
	if writeErr != nil {
		log.WithField("out", out).WithError(writeErr).Warn("GinkgoWriter failed to write output from command.")
	}
	return err
}

var _ = Describe("CNI installation tests", func() {
	var tempDir string
	BeforeEach(func() {
		// Make a temporary directory for this test and build arguments to pass
		// to the CNI container, configuring it to use the temp directory.
		name, err := ioutil.TempDir("/tmp", "")
		Expect(err).NotTo(HaveOccurred())
		tempDir = fmt.Sprintf("/tmp/%s", name)

		// Make subdirectories for where we expect binaries and config to be installed.
		err = os.MkdirAll(tempDir+"/bin", 0755)
		if err != nil {
			Fail("Failed to create directory tmp/bin")
		}
		err = os.MkdirAll(tempDir+"/net.d", 0755)
		if err != nil {
			Fail("Failed to create directory tmp/net.d")
		}
		err = os.MkdirAll(tempDir+"/serviceaccount", 0755)
		if err != nil {
			Fail("Failed to create directory tmp/serviceaccount")
		}

		// Create token file for the Kubernetes client.
		k8sSecret := []byte("my-secret-key")
		tokenFile := fmt.Sprintf("%s/serviceaccount/token", tempDir)
		err = ioutil.WriteFile(tokenFile, k8sSecret, 0755)
		if err != nil {
			Fail(fmt.Sprintf("Failed to write k8s secret file: %v", err))
		}

		// Create a ca.crt - required so the in cluster config works correctly. Since this is just test code,
		// we just need something that parses as an X.509 certificate.
		k8sCA := []byte(`-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUMKY6C1Jk4rHpwHD03qHA2QRyTFYwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xOTA3MDMyMjEyMTVaFw0yMDA3
MDIyMjEyMTVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCZWeLckt9q14it7gXyJbZZDCxzl8pNzQbN6cGEJWo2
9QoqxveW1XKxXrsgH3rTDBjRjxj/ikbaBFLpRTWOrGuyr3dd/sGNByBmFv0HYQ2I
oGPvRt5opDstVK8lnqH22JtrvKJZf7WIoRbmcL5j2p2S5cyvE8JJi3rhA9sMrgwl
wcQMjC3exccaRpA/3XwwsMeAvz08VmrT3BAbpfomf/Vs2JksLTLXtIhBQdPTCthe
AMZwC2oymSy7oZ6GeDkQN34utW3t7sORSSJtSyrfOMLiN9x4RhI70naNcH9b9ESi
5+UKpG9KFcMZgxmRvP042z618UUrZwzdLFpwtmxe1AyJAgMBAAGjUzBRMB0GA1Ud
DgQWBBTV+A1uZr/vrKH1YEoKEWN63uNPKzAfBgNVHSMEGDAWgBTV+A1uZr/vrKH1
YEoKEWN63uNPKzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBN
/a9Xbgzs78HkkemxR4P8Sd9B0hZaSd5clAA/YKsYyUPWIEkKF/fWvO5cm46OdktP
F71CNwp/cwL6Zqcdk+1PpiMYIGpJ0IsqPltn5KdRSbbf2qJyNflKj2EbWAUydyTC
JeLQkW01TNIcFepLRsvjUxlZ572OLaB2GvpndO6ryfFs2dwu96gmUqA+Rk7+h3/h
yvQ/7I8lUKV1hMeCWc2k/x146B/gEgyDl1zUNnJZ/hrKmXqjQy3dkj4HzBePHYND
2oFTq6p93/5bB6PAJknn1ZTGQAXzVKrqau8gHaHw1F+I2p3SuN3NGz4v7HHXo+e4
PuB/TL+u2y+iQUyXxLy3
-----END CERTIFICATE-----`)
		caFile := fmt.Sprintf("%s/serviceaccount/ca.crt", tempDir)
		err = ioutil.WriteFile(caFile, k8sCA, 0755)
		if err != nil {
			Fail(fmt.Sprintf("Failed to write k8s CA file for test: %v", err))
		}
	})

	Context("Install with default values", func() {
		It("Should install bins and config", func() {
			err := runCniContainer(tempDir, true)
			Expect(err).NotTo(HaveOccurred())

			// Get a list of files in the default CNI bin location.
			files, err := ioutil.ReadDir(tempDir + "/bin")
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Could not list the files in %s/bin", tempDir))
			names := []string{}
			for _, file := range files {
				names = append(names, file.Name())
			}

			// Get a list of files in the default location for CNI config.
			files, err = ioutil.ReadDir(tempDir + "/net.d")
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Could not list the files in %s/net.d", tempDir))
			for _, file := range files {
				names = append(names, file.Name())
			}

			Expect(names).To(ContainElement("calico"))
			Expect(names).To(ContainElement("calico-ipam"))
			Expect(names).To(ContainElement("10-calico.conflist"))
		})

		It("Should parse and output a templated config", func() {
			err := runCniContainer(tempDir, true)
			Expect(err).NotTo(HaveOccurred())
			expectFileContents(tempDir+"/net.d/10-calico.conflist", expectedDefaultConfig)
		})
	})

	It("should fail on read-only folder install", func() {
		err := runCniContainer(tempDir, false)
		Expect(err).To(HaveOccurred())
	})

	It("should not fail on one of the folders being read-only", func() {
		err := runCniContainer(tempDir, false, "-v", tempDir+"/secondary-bin-dir:/host/secondary-bin-dir")
		Expect(err).NotTo(HaveOccurred())

		files, err := ioutil.ReadDir(tempDir + "/secondary-bin-dir")
		Expect(err).NotTo(HaveOccurred())

		names := []string{}
		for _, file := range files {
			names = append(names, file.Name())
		}
		Expect(names).To(ContainElement("calico"))
		Expect(names).To(ContainElement("calico-ipam"))
	})

	It("should fail when no directory is writeable", func() {
		err := runCniContainer(tempDir, false, "-v", tempDir+"/secondary-bin-dir:/host/secondary-bin-dir:ro")
		Expect(err).To(HaveOccurred())
	})

	It("should support CNI_CONF_NAME", func() {
		err := runCniContainer(tempDir, true, "-e", "CNI_CONF_NAME=20-calico.conflist")
		Expect(err).NotTo(HaveOccurred())
		expectFileContents(tempDir+"/net.d/20-calico.conflist", expectedDefaultConfig)
	})

	It("should support a custom CNI_NETWORK_CONFIG", func() {
		err := runCniContainer(tempDir, true, "-e", "CNI_NETWORK_CONFIG={}")
		Expect(err).NotTo(HaveOccurred())
		actual, err := ioutil.ReadFile(tempDir + "/net.d/10-calico.conflist")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(actual)).To(Equal("{}"))
	})

	It("should check if the custom CNI_NETWORK_CONFIG is valid json", func() {
		err := runCniContainer(tempDir, true, "-e", "CNI_NETWORK_CONFIG={\"missing quote}")
		Expect(err).To(HaveOccurred())
	})

	It("should use CNI_NETWORK_CONFIG_FILE over CNI_NETWORK_CONFIG", func() {
		// Write the alternate configuration to disk so it can be picked up by
		// the CNI container.
		altConfigFile := tempDir + "/net.d/alternate-config"
		err := ioutil.WriteFile(altConfigFile, []byte(expectedAlternateConfig), 0755)
		Expect(err).NotTo(HaveOccurred())
		err = runCniContainer(
			tempDir, true,
			"-e", "CNI_NETWORK_CONFIG='oops, I used the CNI_NETWORK_CONFIG'",
			"-e", "CNI_NETWORK_CONFIG_FILE=/host/etc/cni/net.d/alternate-config",
		)
		Expect(err).NotTo(HaveOccurred())
		expectFileContents(tempDir+"/net.d/10-calico.conflist", expectedAlternateConfig)
	})

	It("should copy even if plugin is opened", func() {
		// Install the CNI plugin.
		err := runCniContainer(tempDir, true)
		Expect(err).NotTo(HaveOccurred())

		done := make(chan bool)
		defer close(done)

		// Run the portmap plugin in a loop to simulate it being used.
		plug := tempDir + "/bin/portmap"
		go func() {
			for {
				_ = exec.Command(plug).Run()
				select {
				case <-done:
					return
				default:
				}
			}
		}()

		// Install the CNI plugin again. It should succeed.
		err = runCniContainer(tempDir, true)
		Expect(err).NotTo(HaveOccurred())
	})

	Context("copying /calico-secrets", func() {
		var err error
		BeforeEach(func() {
			err = os.MkdirAll(tempDir+"/certs", 0755)
			Expect(err).NotTo(HaveOccurred())
		})

		It("Should not crash or copy when having a hidden file", func() {
			err = ioutil.WriteFile(tempDir+"/certs/.hidden", []byte("doesn't matter"), 0644)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write hidden file: %v", err))
			err = runCniContainer(tempDir, true, "-v", tempDir+"/certs:/calico-secrets")
			Expect(err).NotTo(HaveOccurred())
			_, err = os.Open(tempDir + "/net.d/calico-tls/.hidden")
			Expect(err).To(HaveOccurred())
		})
		It("Should copy a non-hidden file", func() {
			err = ioutil.WriteFile(tempDir+"/certs/etcd-cert", []byte("doesn't matter"), 0644)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))
			err = runCniContainer(tempDir, true, "-v", tempDir+"/certs:/calico-secrets", "-e", "CNI_NETWORK_CONFIG={\"etcd_cert\": \"__ETCD_CERT_FILE__\"}")
			Expect(err).NotTo(HaveOccurred())
			file, err := os.Open(tempDir + "/net.d/calico-tls/etcd-cert")
			Expect(err).NotTo(HaveOccurred())
			err = file.Close()
			Expect(err).NotTo(HaveOccurred())

			// Expect the config to have the correct value filled in.
			expectedConfig := "{\"etcd_cert\": \"/etc/cni/net.d/calico-tls/etcd-cert\"}"
			expectFileContents(tempDir+"/net.d/10-calico.conflist", expectedConfig)
		})
	})
})

var _ = Describe("file comparison tests", func() {
	var err error
	var tempDir string
	BeforeEach(func() {
		// Make a temporary directory for this test and build arguments to pass
		// to the CNI container, configuring it to use the temp directory.
		tempDir, err = ioutil.TempDir("/tmp", "")
		Expect(err).NotTo(HaveOccurred())
	})

	It("should compare two equal files", func() {
		// Write two identical files.
		err := ioutil.WriteFile(tempDir+"/srcFile", []byte("doesn't matter"), 0644)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))
		err = ioutil.WriteFile(tempDir+"/dstFile", []byte("doesn't matter"), 0644)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))

		// Assert that they are equal.
		match, err := destinationUptoDate(tempDir+"/srcFile", tempDir+"/dstFile")
		Expect(err).NotTo(HaveOccurred())
		Expect(match).To(Equal(true))
	})

	It("should compare two unequal files", func() {
		// Write two files with different contents.
		err := ioutil.WriteFile(tempDir+"/srcFile", []byte("doesn't matter"), 0644)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))
		err = ioutil.WriteFile(tempDir+"/dstFile", []byte("it does matter"), 0644)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))

		// Assert that they are not equal.
		match, err := destinationUptoDate(tempDir+"/srcFile", tempDir+"/dstFile")
		Expect(err).NotTo(HaveOccurred())
		Expect(match).To(Equal(false))
	})

	It("should compare two unequal files of the same size", func() {
		// Write two files with different contents, but same total size.
		err := ioutil.WriteFile(tempDir+"/srcFile", []byte("foobar"), 0644)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))
		err = ioutil.WriteFile(tempDir+"/dstFile", []byte("barfoo"), 0644)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))

		// Assert that they are not equal.
		match, err := destinationUptoDate(tempDir+"/srcFile", tempDir+"/dstFile")
		Expect(err).NotTo(HaveOccurred())
		Expect(match).To(Equal(false))
	})

	It("should compare two files with differing file modes", func() {
		// Write two identical files.
		err := ioutil.WriteFile(tempDir+"/srcFile", []byte("doesn't matter"), 0644)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))
		err = ioutil.WriteFile(tempDir+"/dstFile", []byte("doesn't matter"), 0644)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write file: %v", err))

		// For whatever reason, we need to explicitly chmod the file to get the permissions to change.
		Expect(os.Chmod(tempDir+"/dstFile", 0777)).NotTo(HaveOccurred())

		// Assert that they are not equal.
		match, err := destinationUptoDate(tempDir+"/srcFile", tempDir+"/dstFile")
		Expect(err).NotTo(HaveOccurred())
		Expect(match).To(Equal(false))
	})
})

func expectFileContents(filename, expected string) {
	actual, err := ioutil.ReadFile(filename)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to read file "+filename)
	ExpectWithOffset(0, string(actual)).To(Equal(expected), fmt.Sprintf(
		"actual file (%s) differed from expected contents.\nActual: (%s)\nExpected: (%s)",
		filename, string(actual), string(expected)))
}
