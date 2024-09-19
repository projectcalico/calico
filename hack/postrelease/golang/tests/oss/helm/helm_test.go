package oss

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/hack/postrelease/golang/pkg/helm"
)

var calicoReleaseTag = os.Getenv("CALICO_VERSION")

func TestMain(m *testing.M) {
	failed := false
	if calicoReleaseTag == "" {
		fmt.Println("Missing CALICO_VERSION variable!")
		failed = true
	}
	if failed {
		fmt.Println("Please set the appropriate variables and then re-run the test suite")
		os.Exit(2)
	}

	v := m.Run()
	os.Exit(v)
}

func Test_ValidateHelmChart(t *testing.T) {
	t.Parallel()
	t.Run("HelmChartIsInIndex", func(t *testing.T) {
		t.Parallel()
		index, err := helm.GetIndex()
		assert.NoError(t, err)
		assert.True(t, index.CheckVersionIsPublished(calicoReleaseTag))
	})

	t.Run("HelmChartCanBeLoaded", func(t *testing.T) {
		t.Parallel()
		err := helm.LoadArchiveForVersion(calicoReleaseTag)
		assert.NoError(t, err)
	})
}
