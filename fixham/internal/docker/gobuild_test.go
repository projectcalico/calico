package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewGoBuild(t *testing.T) {
	image := NewGoBuild("v1.0.0")
	assert.Equal(t, defaultGoBuildName, image.imageName, "Unexpected image name")
	assert.Equal(t, "v1.0.0", image.imageVersion, "Unexpected image version")
}

func TestGoBuildImage(t *testing.T) {
	image := GoBuildImage{
		imageName:    "calico/go-build",
		imageVersion: "v1.0.0",
	}
	assert.Equal(t, "calico/go-build:v1.0.0", image.Image(), "Unexpected image name")
}

func TestNewGoBuildRunner(t *testing.T) {
	repo := "github.com/example/repo"
	runner := MustGoBuildRunner("v1.0.0", repo, "")
	assert.Equal(t, repo, runner.packageName, "Unexpected package name")
	assert.Equal(t, defaultGoBuildName, runner.GoBuildImage.imageName, "Unexpected image name")
}

func TestMustGoBuildRunner(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	assert.NotNil(t, runner, "Unexpected nil runner")
}

func TestGoBuildRunnerWithEnv(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	env := []string{"ENVVAR1=value1", "ENVVAR2=value2"}
	expectedEnv := runner.containerConfig.Env
	expectedEnv = append(expectedEnv, env...)
	runner.WithEnv(env...)
	assert.Equal(t, expectedEnv, runner.containerConfig.Env, "Unexpected environment variables")
}

func TestGoBuildRunnergetBindMountSource(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	dir := modCacheDir
	_, err := runner.UsingGoModCache(dir)
	assert.Nil(t, err, "Unexpected error")
	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}

func TestGoBuildRunnergetBindMountSourceNone(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	target := "/container/path"
	assert.Equal(t, "", runner.getBindMountSource(target), "Unexpected bind mount source")
}

func TestGoBuildRunnerhasBindNot(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	bind := "/host/path:/container/path"
	assert.False(t, runner.hasBind(bind), "unexpected bind mount")
}

func TestGoBuildRunnerremoveBindMount(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	dir := modCacheDir
	_, err := runner.UsingGoModCache(dir)
	assert.Nil(t, err, "Unexpected error")
	runner.removeBindMount(modCacheDir)
	assert.NotContains(t, runner.hostConfig.Binds, dir, "Unexpected bind mount source")
}

func TestGoBuildRunnerWithVolume(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	volumes := []string{"/host/path:/container/path"}
	expectedVolumes := runner.hostConfig.Binds
	expectedVolumes = append(expectedVolumes, volumes...)
	_, err := runner.WithVolume(volumes...)
	assert.Nil(t, err, "Unexpected error")
	assert.Equal(t, expectedVolumes, runner.hostConfig.Binds, "Unexpected volumes")
}

func TestGoBuildRunnerUsingGoModCache(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	dir := modCacheDir
	_, err := runner.UsingGoModCache(dir)
	assert.Nil(t, err, "Unexpected error")
	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}

func TestGoBuildRunnerUsingGoModCacheMultiple(t *testing.T) {
	runner := MustGoBuildRunner("v1.0.0", "github.com/example/repo", "")
	dir := modCacheDir
	_, err := runner.UsingGoModCache(dir)
	assert.Nil(t, err, "Unexpected error")
	_, err = runner.UsingGoModCache(dir)
	assert.Nil(t, err, "Unexpected error")
	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}
