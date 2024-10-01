package driver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"

	. "github.com/onsi/gomega"
)

func testRetrievePodInfoFromFile(g *WithT, setup podInfoTestSetup, volumeID, credsJSON string, checkErr validateReturnError) {
	err := setup(volumeID, credsJSON)
	g.Expect(err).NotTo(HaveOccurred(), "Test setup failed")

	nodeServiceConfig := ConfigurationOptions{
		NodeAgentCredentialsHomeDir: "/tmp",
	}
	nodeService := &nodeService{&nodeServiceConfig}
	_, err = nodeService.retrievePodInfoFromFile(volumeID)
	g.Expect(checkErr(err)).NotTo(HaveOccurred(), "Error check failed")
}

var testTableRetrievePodInfoFromFile = []struct {
	description string
	volumeID    string
	credsJSON   string
	setupTest   podInfoTestSetup
	validate    validateReturnError
}{
	{
		description: "Test valid JSON",
		volumeID:    "volume0",
		credsJSON: `{
			"uid": "abc-def-123-456",
			"workload": "test-workload",
			"namespace": "test-ns",
			"serviceAccount": "test-sa"
		}`,
		setupTest: createRealTempJSONFile,
		validate:  expectNoError,
	},
	{
		description: "Test invalid JSON",
		volumeID:    "volumeBadJSONFIle",
		credsJSON: `{
			sfljksflkjsdf
		}`,
		setupTest: createRealTempJSONFile,
		validate: func(err error) error {
			// Expect to receive a json.SyntaxError.
			se := &json.SyntaxError{}
			if err == nil || !errors.As(err, &se) {
				return fmt.Errorf("Expected json.SyntaxError, but got: %w", err)
			}
			return nil
		},
	},
	{
		description: "Test missing creds file",
		volumeID:    "volumeMissingFilename",
		credsJSON:   ``,
		setupTest:   dontCreateCredsFile,
		validate: func(err error) error {
			if err == nil || !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("Expected fs.ErrNotExist, but got: %w", err)
			}
			return nil
		},
	},
}

func TestRetrievePodInfoFromFile(t *testing.T) {
	for _, tt := range testTableRetrievePodInfoFromFile {
		t.Run(tt.description, func(t *testing.T) {
			g := NewWithT(t)
			testRetrievePodInfoFromFile(g, tt.setupTest, tt.volumeID, tt.credsJSON, tt.validate)
		})
	}
}

// Create (or dont) the podInfo test file at start of test.
type podInfoTestSetup func(filename, contents string) error

// Validate the returned-error from the function under test.
// If the correct error is received, return nil, otherwise return the error, optionally wrapped.
type validateReturnError func(err error) error

func expectNoError(err error) error {
	return err
}

func createRealTempJSONFile(name, contents string) error {
	tmpFile, err := os.Create("/tmp/" + name + ".json")
	if err != nil {
		return fmt.Errorf("Couldn't create temp JSON file: %w", err)
	}
	defer tmpFile.Close()

	_, err = tmpFile.Write([]byte(contents))
	if err != nil {
		return fmt.Errorf("Couldn't write to temp JSON file: %w", err)
	}

	return nil
}

// For testing file-not-exists error handling.
func dontCreateCredsFile(_, _ string) error { return nil }
