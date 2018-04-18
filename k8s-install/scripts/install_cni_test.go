package scripts_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

var secretFile = "tmp/serviceaccount/token"

// runCniContainer will run install-cni.sh.
// TODO: We should be returning an error if the command fails, there currently is
// not a way to get that from the container package.
func runCniContainer(extraArgs ...string) error {
	name := "cni"

	// Get the CWD for mounting directories into container.
	cwd, err := os.Getwd()
	if err != nil {
		Fail("Could not get CWD")
	}

	// Ensure the install cni container was not left over from another run.
	out, err := exec.Command("docker", "rm", name).CombinedOutput()
	if err != nil {
		if !strings.Contains(string(out), "No such container: "+name) {
			Fail(fmt.Sprintf("Error running docker command: %s", out))
		}
	}

	// Assemble our arguments.
	args := []string{
		"run", "--rm", "--name", name,
		"-e", "SLEEP=false",
		"-e", "KUBERNETES_SERVICE_HOST=127.0.0.1",
		"-e", "KUBERNETES_SERVICE_PORT=8080",
		"-v", cwd + "/tmp/bin:/host/opt/cni/bin",
		"-v", cwd + "/tmp/net.d:/host/etc/cni/net.d",
		"-v", cwd + "/tmp/serviceaccount:/var/run/secrets/kubernetes.io/serviceaccount",
	}
	args = append(args, extraArgs...)
	image := fmt.Sprintf("%s", os.Getenv("CONTAINER_NAME"))
	args = append(args, image, "/install-cni.sh")

	out, err = exec.Command("docker", args...).CombinedOutput()
	GinkgoWriter.Write(out)

	return err
}

// cleanup uses the calico/cni container to cleanup after itself as it creates
// things as root.
func cleanup() {
	cwd, err := os.Getwd()
	if err != nil {
		Fail("Could not get CWD")
	}
	out, err := exec.Command("docker", "run", "--rm", "--name", "cni_cleanup",
		"-e", "SLEEP=false",
		"-e", "KUBERNETES_SERVICE_HOST=127.0.0.1",
		"-e", "KUBERNETES_SERVICE_PORT=8080",
		"-v", cwd+"/tmp/bin:/host/opt/cni/bin",
		"-v", cwd+"/tmp/net.d:/host/etc/cni/net.d",
		"-v", cwd+"/tmp/serviceaccount:/var/run/secrets/kubernetes.io/serviceaccount",
		fmt.Sprintf("%s", os.Getenv("CONTAINER_NAME")),
		"sh", "-c", "rm -rf /host/opt/cni/bin/* /host/etc/cni/net.d/*").CombinedOutput()

	if err != nil {
		Fail(fmt.Sprintf("Failed to clean up root owned files: %s", string(out)))
	}
}

var _ = BeforeSuite(func() {
	// Make the directories we'll need for storing files.
	err := os.MkdirAll("tmp/bin", 0755)
	if err != nil {
		Fail("Failed to create directory tmp/bin")
	}
	err = os.MkdirAll("tmp/net.d", 0755)
	if err != nil {
		Fail("Failed to create directory tmp/net.d")
	}
	err = os.MkdirAll("tmp/serviceaccount", 0755)
	if err != nil {
		Fail("Failed to create directory tmp/serviceaccount")
	}
	cleanup()

	// Create a secrets file for parsing.
	k8sSecret := []byte("my-secret-key")
	err = ioutil.WriteFile(secretFile, k8sSecret, 0755)
	if err != nil {
		Fail(fmt.Sprintf("Failed to write k8s secret file: %v", err))
	}
})

var _ = AfterSuite(func() {
	err := os.RemoveAll("tmp")
	if err != nil {
		fmt.Println("Failed to clean up directories")
	}
})

var _ = Describe("install-cni.sh tests", func() {
	AfterEach(func() {
		cleanup()
	})

	Describe("Run install-cni", func() {
		Context("With default values", func() {
			It("Should install bins and config", func() {
				err := runCniContainer()
				Expect(err).NotTo(HaveOccurred())

				// Get a list of files in the defualt CNI bin location.
				files, err := ioutil.ReadDir("tmp/bin")
				if err != nil {
					Fail("Could not list the files in tmp/bin")
				}
				names := []string{}
				for _, file := range files {
					names = append(names, file.Name())
				}

				// Get a list of files in the default location for CNI config.
				files, err = ioutil.ReadDir("tmp/net.d")
				if err != nil {
					Fail("Could not list the files in tmp/net.d")
				}
				for _, file := range files {
					names = append(names, file.Name())
				}

				Expect(names).To(ContainElement("calico"))
				Expect(names).To(ContainElement("calico-ipam"))
				Expect(names).To(ContainElement("10-calico.conf"))
			})
			It("Should parse and output a templated config", func() {
				err := runCniContainer()
				Expect(err).NotTo(HaveOccurred())

				expectedFile := "expected_10-calico.conf"

				var expected = []byte{}
				if file, err := os.Open(expectedFile); err != nil {
					Fail("Could not open " + expectedFile + " for reading")
				} else {
					_, err := file.Read(expected)
					if err != nil {
						Fail("Could not read from expected_10-calico.conf")
					}
					err = file.Close()
					if err != nil {
						fmt.Println("Failed to close expected_10-calico.conf")
					}
				}

				var received = []byte{}
				if file, err := os.Open("tmp/net.d/10-calico.conf"); err != nil {
					Fail("Could not open 10-calico.conf for reading")
				} else {
					_, err := file.Read(received)
					if err != nil {
						Fail("Could not read from 10-calico.conf")
					}
					err = file.Close()
					if err != nil {
						fmt.Println("Failed to close 10-calico.conf")
					}
				}

				Expect(expected).To(Equal(received))
			})
		})

		Context("With modified env vars", func() {
			It("Should rename '10-calico.conf' to '10-calico.conflist'", func() {
				err := runCniContainer("-e", "CNI_CONF_NAME=10-calico.conflist")
				Expect(err).NotTo(HaveOccurred())

				expectedFile := "expected_10-calico.conf"

				var expected = []byte{}
				if file, err := os.Open(expectedFile); err != nil {
					Fail("Could not open " + expectedFile + " for reading")
				} else {
					_, err := file.Read(expected)
					if err != nil {
						Fail("Could not read from expected_10-calico.conf")
					}
					err = file.Close()
					if err != nil {
						fmt.Println("Failed to close expected_10-calico.conf")
					}
				}

				var received = []byte{}
				if file, err := os.Open("tmp/net.d/10-calico.conflist"); err != nil {
					Fail("Could not open 10-calico.conflist for reading")
				} else {
					_, err := file.Read(received)
					if err != nil {
						Fail("Could not read from 10-calico.conflist")
					}
					err = file.Close()
					if err != nil {
						fmt.Println("Failed to close 10-calico.conflist")
					}
				}

				Expect(expected).To(Equal(received))
			})
		})

		Context("copying /calico-secrets", func() {
			err := os.MkdirAll("tmp/certs", 0755)
			if err != nil {
				Fail("Failed to create directory tmp/bin")
			}

			It("Should not crash or copy when having a hidden file", func() {
				err = ioutil.WriteFile("tmp/certs/.hidden", []byte("doesn't matter"), 0755)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write hidden file: %v", err))

				cwd, _ := os.Getwd()
				err = runCniContainer("-v", cwd+"/tmp/certs:/calico-secrets")
				Expect(err).NotTo(HaveOccurred())
				_, err = os.Open("tmp/net.d/calico-tls/.hidden")
				Expect(err).To(HaveOccurred())
			})
			It("Should copy a non-hidden file", func() {
				err = ioutil.WriteFile("tmp/certs/nothidden", []byte("doesn't matter"), 0755)
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to write hidden file: %v", err))

				cwd, _ := os.Getwd()
				err = runCniContainer("-v", cwd+"/tmp/certs:/calico-secrets")
				Expect(err).NotTo(HaveOccurred())
				_, err = os.Open("tmp/net.d/calico-tls/nothidden")
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
