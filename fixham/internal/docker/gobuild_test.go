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
	image := NewGoBuild("")
	expectedImage := defaultGoBuildName + ":" + defaultGoBuildVersion
	assert.Equal(t, expectedImage, image.Image(), "Unexpected image name")
}

func TestGoBuildImageDefaults(t *testing.T) {
	image := GoBuildImage{}
	expectedImage := defaultGoBuildName + ":" + defaultGoBuildVersion
	assert.Equal(t, expectedImage, image.Image(), "Unexpected image name")
}

func TestNewGoBuildRunner(t *testing.T) {
	repo := "github.com/example/repo"
	runner, _ := NewGoBuildRunner(repo, "")
	assert.Equal(t, repo, runner.packageName, "Unexpected package name")
	assert.Equal(t, defaultGoBuildName, runner.GoBuildImage.imageName, "Unexpected image name")
	assert.Equal(t, defaultGoBuildVersion, runner.GoBuildImage.imageVersion, "Unexpected image version")
}

func TestGoBuildRunnerWithVersion(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	version := "v1.0.0"
	runner.WithVersion(version)
	assert.Equal(t, version, runner.GoBuildImage.imageVersion, "Unexpected image version")
}

func TestGoBuildRunnerVersion(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	assert.Equal(t, defaultGoBuildVersion, runner.Version(), "Unexpected image version")

}

func TestGoBuildRunnerWithEnv(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	env := []string{"ENVVAR1=value1", "ENVVAR2=value2"}
	expectedEnv := runner.containerConfig.Env
	expectedEnv = append(expectedEnv, env...)
	runner.WithEnv(env...)
	assert.Equal(t, expectedEnv, runner.containerConfig.Env, "Unexpected environment variables")
}

func TestGoBuildRunnergetBindMountSource(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	dir := "/go/pkg/mod"
	runner.UsingGoModCache(dir)
	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}

func TestGoBuildRunnergetBindMountSourceNone(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	target := "/container/path"
	assert.Equal(t, "", runner.getBindMountSource(target), "Unexpected bind mount source")
}

func TestGoBuildRunnerhasBind(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	bind := "/host/path:/container/path"
	runner.WithVolume(bind)
	assert.True(t, runner.hasBind(bind), "expected bind mount")
}

func TestGoBuildRunnerhasBindNot(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	bind := "/host/path:/container/path"
	assert.False(t, runner.hasBind(bind), "unexpected bind mount")
}

func TestGoBuildRunnerremoveBindMount(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	dir := "/go/pkg/mod"
	runner.UsingGoModCache(dir)
	runner.removeBindMount(modCacheDir)
	assert.NotContains(t, runner.hostConfig.Binds, dir, "Unexpected bind mount source")
}

func TestGoBuildRunnerWithVolume(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	volumes := []string{"/host/path:/container/path"}
	expectedVolumes := runner.hostConfig.Binds
	expectedVolumes = append(expectedVolumes, volumes...)
	runner.WithVolume(volumes...)
	assert.Equal(t, expectedVolumes, runner.hostConfig.Binds, "Unexpected volumes")
}

func TestGoBuildRunnerUsingGoModCache(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	dir := "/go/pkg/mod"
	runner.UsingGoModCache(dir)
	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}

func TestGoBuildRunnerUsingGoModCacheMultiple(t *testing.T) {
	runner, _ := NewGoBuildRunner("github.com/example/repo", "")
	dir := "/go/pkg/mod"
	runner.UsingGoModCache(dir)
	runner.UsingGoModCache(dir)
	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}
