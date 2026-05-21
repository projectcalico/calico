package driver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	defer func() { _ = tmpFile.Close() }()

	_, err = tmpFile.Write([]byte(contents))
	if err != nil {
		return fmt.Errorf("Couldn't write to temp JSON file: %w", err)
	}

	return nil
}

// For testing file-not-exists error handling.
func dontCreateCredsFile(_, _ string) error { return nil }

// TestValidateVolumeID asserts that VolumeId values that would let a caller of
// the CSI gRPC socket break out of NodeAgent*HomeDir are rejected before any
// filesystem operation runs. The driver concatenates VolumeId into host paths
// in NodePublishVolume / NodeUnpublishVolume; without this gate, traversal
// segments would let a caller of the socket act on arbitrary host paths under
// the root, privileged DaemonSet's mount tree.
func TestValidateVolumeID(t *testing.T) {
	rejected := []string{
		"",                       // missing
		"..",                     // pure parent ref
		"../etc/poc",             // traversal
		"foo/bar",                // path separator
		"/abs/poc",               // absolute path
		"a/b",                    // any slash
		"valid..name",            // ".." substring
		" leading-space",         // disallowed char
		"with space",             // disallowed char
		"with\nnewline",          // disallowed char
		"with;semicolon",         // disallowed char
		strings.Repeat("a", 129), // too long
	}
	for _, vid := range rejected {
		t.Run(fmt.Sprintf("reject/%q", vid), func(t *testing.T) {
			g := NewWithT(t)
			err := validateVolumeID(vid)
			g.Expect(err).To(HaveOccurred(), "expected rejection for VolumeID %q", vid)
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument),
				"VolumeID %q must be rejected as InvalidArgument", vid)
		})
	}

	accepted := []string{
		"csi-5136cc95849bc789e7f53a2466693a5e63189a8e99e3223706f1f7b804624e32", // kubelet inline-ephemeral shape
		"vol_01",
		"vol-01",
		"vol.01",
		"a",
		strings.Repeat("a", 128), // exactly at max length
	}
	for _, vid := range accepted {
		t.Run(fmt.Sprintf("accept/%q", vid), func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(validateVolumeID(vid)).To(Succeed(),
				"VolumeID %q must be accepted", vid)
		})
	}
}
