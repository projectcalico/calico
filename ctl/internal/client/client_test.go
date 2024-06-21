package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	c := NewClient("testPackage")
	assert.NotNil(t, c)
	assert.Equal(t, "testPackage", c.packageName)
}

func TestWithGoBuildVersion(t *testing.T) {
	c := NewClient("testPackage")
	c.WithGoBuildVersion("1.2.3")
	assert.Equal(t, "1.2.3", c.goBuildRunner.Version())
}
