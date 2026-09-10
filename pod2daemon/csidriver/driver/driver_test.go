package driver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Compile-time assertions that the driver satisfies the CSI server interfaces.
// Since CSI spec v1.10.0 these interfaces require embedding the generated
// Unimplemented*Server structs (forward compatibility), so these guard against
// a regression where that embedding is dropped.
var (
	_ csi.IdentityServer = (*Driver)(nil)
	_ csi.NodeServer     = (*Driver)(nil)
)

func testRetrievePodInfoFromFile(g *WithT, setup podInfoTestSetup, volumeID, credsJSON string, checkErr validateReturnError) {
	err := setup(volumeID, credsJSON)
	g.Expect(err).NotTo(HaveOccurred(), "Test setup failed")

	nodeServiceConfig := ConfigurationOptions{
		NodeAgentCredentialsHomeDir: "/tmp",
	}
	nodeService := &nodeService{config: &nodeServiceConfig}
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

// TestValidateVolumeID covers the CSI spec requirement that VolumeId be set.
// Format is deliberately not constrained — see the function's godoc.
// Path-traversal protection is independently covered by TestJoinUnderBase.
func TestValidateVolumeID(t *testing.T) {
	t.Run("reject/empty", func(t *testing.T) {
		g := NewWithT(t)
		err := validateVolumeID("")
		g.Expect(err).To(HaveOccurred())
		g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
	})

	// Anything non-empty passes — kubelet's current sha256-hex shape, future
	// shapes, weird characters, traversal segments. Safety is provided by
	// joinUnderBase at the FS-op sites, not here.
	accepted := []string{
		"csi-5136cc95849bc789e7f53a2466693a5e63189a8e99e3223706f1f7b804624e32",
		".",
		"..",
		"foo/bar",
		"with space",
		"with\nnewline",
		strings.Repeat("a", 1024),
	}
	for _, vid := range accepted {
		t.Run(fmt.Sprintf("accept/%q", vid), func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(validateVolumeID(vid)).To(Succeed())
		})
	}
}

// TestJoinUnderBase covers the path-traversal safety property: paths that
// resolve outside base are rejected, paths that stay under base are returned
// joined.
func TestJoinUnderBase(t *testing.T) {
	const base = "/var/run/nodeagent/mount"

	rejected := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"dot", "."},
		{"dotdot", ".."},
		{"single-traversal", "../etc/poc"},
		{"deep-traversal", "../../../../etc/poc"},
	}
	for _, tc := range rejected {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := joinUnderBase(base, tc.in)
			g.Expect(err).To(HaveOccurred(), "expected rejection for %q", tc.in)
			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
		})
	}

	accepted := []struct {
		name string
		in   string
		want string
	}{
		{"flat-name", "csi-abc", "/var/run/nodeagent/mount/csi-abc"},
		{"with-suffix", "csi-abc.json", "/var/run/nodeagent/mount/csi-abc.json"},
	}
	for _, tc := range accepted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			g := NewWithT(t)
			got, err := joinUnderBase(base, tc.in)
			g.Expect(err).NotTo(HaveOccurred(), "unexpected rejection of %q", tc.in)
			g.Expect(got).To(Equal(tc.want))
		})
	}

	// RetrieveConfig() assembles base paths via string concatenation, so a
	// base with a trailing slash or duplicate separator can reach here. The
	// function must normalize base before the prefix check.
	nonNormalized := []string{
		"/var/run/nodeagent/mount/",
		"/var/run/nodeagent//mount",
		"/var/run/nodeagent/mount///",
	}
	for _, b := range nonNormalized {
		t.Run(fmt.Sprintf("normalizes-base/%q", b), func(t *testing.T) {
			g := NewWithT(t)
			got, err := joinUnderBase(b, "csi-abc")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(got).To(Equal("/var/run/nodeagent/mount/csi-abc"))

			_, err = joinUnderBase(b, "..")
			g.Expect(err).To(HaveOccurred(), "traversal must still be rejected after normalization")
		})
	}
}
