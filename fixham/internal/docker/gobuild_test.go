package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewGoBuild(t *testing.T) {
	image := NewGoBuild()

	assert.Equal(t, defaultGoBuildName, image.imageName, "Unexpected image name")
	assert.Equal(t, defaultGoBuildVersion, image.imageVersion, "Unexpected image version")
}

func TestGoBuild_Image(t *testing.T) {
	image := NewGoBuild()

	expectedImage := defaultGoBuildName + ":" + defaultGoBuildVersion

	assert.Equal(t, expectedImage, image.Image(), "Unexpected image name")
}

func TestGoBuild_ImageDefaults(t *testing.T) {
	image := GoBuildImage{}

	expectedImage := defaultGoBuildName + ":" + defaultGoBuildVersion

	assert.Equal(t, expectedImage, image.Image(), "Unexpected image name")
}

func TestNewGoBuildRunner(t *testing.T) {
	repo := "github.com/example/repo"

	runner := NewGoBuildRunner(repo)

	assert.Equal(t, repo, runner.packageName, "Unexpected package name")
	assert.Equal(t, defaultGoBuildName, runner.GoBuildImage.imageName, "Unexpected image name")
	assert.Equal(t, defaultGoBuildVersion, runner.GoBuildImage.imageVersion, "Unexpected image version")
}

func TestGoBuildRunner_WithVersion(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	version := "v1.0.0"

	runner.WithVersion(version)

	assert.Equal(t, version, runner.GoBuildImage.imageVersion, "Unexpected image version")
}

func TestGoBuildRunner_Version(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")

	assert.Equal(t, defaultGoBuildVersion, runner.Version(), "Unexpected image version")

}

func TestGoBuildRunner_WithEnv(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	env := []string{"ENV_VAR1=value1", "ENV_VAR2=value2"}

	expectedEnv := runner.containerConfig.Env
	expectedEnv = append(expectedEnv, env...)

	runner.WithEnv(env...)

	assert.Equal(t, expectedEnv, runner.containerConfig.Env, "Unexpected environment variables")
}

func TestGoBuildRunner_getBindMountSource(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	dir := "/go/pkg/mod"

	runner.UsingGoModCache(dir)

	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}

func TestGoBuildRunner_getBindMountSourceNone(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	target := "/container/path"

	assert.Equal(t, "", runner.getBindMountSource(target), "Unexpected bind mount source")
}

func TestGoBuildRunner_hasBind(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	bind := "/host/path:/container/path"

	runner.WithVolume(bind)

	assert.True(t, runner.hasBind(bind), "expected bind mount")
}

func TestGoBuildRunner_hasBindNot(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	bind := "/host/path:/container/path"

	assert.False(t, runner.hasBind(bind), "unexpected bind mount")
}

func TestGoBuildRunner_removeBindMount(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	dir := "/go/pkg/mod"

	runner.UsingGoModCache(dir)
	runner.removeBindMount(modCacheDir)

	assert.NotContains(t, runner.hostConfig.Binds, dir, "Unexpected bind mount source")
}

func TestGoBuildRunner_WithVolume(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	volumes := []string{"/host/path:/container/path"}

	expectedVolumes := runner.hostConfig.Binds
	expectedVolumes = append(expectedVolumes, volumes...)

	runner.WithVolume(volumes...)

	assert.Equal(t, expectedVolumes, runner.hostConfig.Binds, "Unexpected volumes")
}

func TestGoBuildRunner_WithBashCmd(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	cmd := "echo 'Hello, World!'"

	runner.WithBashCmd(cmd)

	assert.Equal(t, []string{"bash", "-c", cmd}, runner.cmd, "Unexpected command")
}

func TestGoBuildRunner_WithShCmd(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	cmd := "echo 'Hello, World!'"

	runner.WithShCmd(cmd)

	assert.Equal(t, []string{"sh", "-c", cmd}, runner.cmd, "Unexpected command")
}

func TestGoBuildRunner_UsingGoModCache(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	dir := "/go/pkg/mod"

	runner.UsingGoModCache(dir)

	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}

func TestGoBuildRunner_UsingGoModCacheMultiple(t *testing.T) {
	runner := NewGoBuildRunner("github.com/example/repo")
	dir := "/go/pkg/mod"

	runner.UsingGoModCache(dir)
	runner.UsingGoModCache(dir)

	assert.Equal(t, dir, runner.getBindMountSource(modCacheDir), "Unexpected bind mount source")
}
