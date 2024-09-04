package oss

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/hack/postrelease/golang/pkg/openstack"
)

var calicoReleaseTag = os.Getenv("CALICO_VERSION")

func TestMain(m *testing.M) {
	failed := false
	if calicoReleaseTag == "" {
		fmt.Println("Missing CALICO_RELEASE variable!")
		failed = true
	}
	if failed {
		fmt.Println("Please set the appropriate variables and then re-run the test suite")
		os.Exit(2)
	}

	v := m.Run()
	os.Exit(v)
}

func Test_OpenStackPublished(t *testing.T) {
	packageList := openstack.GetPackages(calicoReleaseTag)
	for packagePlatform, packageObjList := range packageList {
		for _, packageObj := range packageObjList {
			testName := fmt.Sprintf("%s/%s/%s/%s %s", packagePlatform, packageObj.OSVersion, packageObj.Arch, packageObj.Component, packageObj.Version)
			t.Run(testName, func(t *testing.T) {
				t.Parallel()
				resp, err := packageObj.Head()
				assert.NoError(t, err)
				assert.Equal(t, 200, resp.StatusCode, "blahblah")
			})
		}
	}
}
