package driver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

type podInfoTestSetup func(filename, contents string)

var _ = DescribeTable("Test func: retrievePodInfoFromFile", testRetrievePodInfoFromFile,
	Entry("Test valid JSON",
		createRealTempJSONFile,
		"volume0",
		`{
			"uid": "abc-def-123-456",
			"workload": "test-workload",
			"namespace": "test-ns",
			"serviceAccount": "test-sa"
		}`,
		func(err error) error {
			return err
		},
	),
	Entry("Test invalid JSON",
		createRealTempJSONFile,
		"volumeBadJSONFIle",
		`{
			sfljksflkjsdf
		}`,
		func(err error) error {
			se := &json.SyntaxError{}
			if err == nil || !errors.As(err, &se) {
				return fmt.Errorf("Expected json.SyntaxError, but got: %w", err)
			}
			return nil
		},
	),
	Entry("Test missing creds file",
		dontCreateCredsFile,
		"volumeMissingFilename", ``,
		func(err error) error {
			if err == nil || !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("Expected fs.ErrNotExist, but got: %w", err)
			}
			return nil
		},
	),
)

func testRetrievePodInfoFromFile(setup podInfoTestSetup, volumeID, credsJSON string, checkErr func(error) error) {
	setup(volumeID, credsJSON)

	nodeServiceConfig := ConfigurationOptions{
		NodeAgentCredentialsHomeDir: "/tmp",
	}
	nodeService := &nodeService{&nodeServiceConfig}
	_, err := nodeService.retrievePodInfoFromFile(volumeID)
	Expect(checkErr(err)).NotTo(HaveOccurred(), "Error check failed")
}

func createRealTempJSONFile(name, contents string) {
	tmpFile, err := os.Create("/tmp/" + name + ".json")
	Expect(err).NotTo(HaveOccurred(), "Test setup failed - couldn't create a temp file")
	defer tmpFile.Close()

	b, err := tmpFile.Write([]byte(contents))
	Expect(err).NotTo(HaveOccurred(), "Test setup failed - couldn't write to pod-info file")

	By(fmt.Sprintf("Writing %d bytes to %s", b, tmpFile.Name()))
}

// For testing file-not-exists error handling.
func dontCreateCredsFile(_, _ string) {}
