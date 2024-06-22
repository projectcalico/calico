package docker

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/fixham/internal/file"
)

const (
	defaultGoBuildName    = "calico/go-build"
	defaultGoBuildVersion = "v0.91"

	modCacheDir = "/go/pkg/mod"
	goCacheDir  = "/go-cache"
)

// GoBuildImage is the struct for the go-build image
// i.e calico/go-build:<version>
type GoBuildImage struct {
	imageName    string
	imageVersion string
}

// NewGoBuild returns a new GoBuildImage
// with default image name and version
func NewGoBuild() GoBuildImage {
	return GoBuildImage{
		imageName:    defaultGoBuildName,
		imageVersion: defaultGoBuildVersion,
	}
}

// Image returns the image name and version
// i.e "calico/go-build:<version>"
func (g GoBuildImage) Image() string {
	name := g.imageName
	if name == "" {
		name = defaultGoBuildName
	}
	version := g.imageVersion
	if version == "" {
		version = defaultGoBuildVersion
	}
	return name + ":" + version
}

// GoBuildRunner is the struct for running go-build image
// for a specific package name
type GoBuildRunner struct {
	GoBuildImage
	DockerRunner
	cmd             []string
	packageName     string
	repoVolume      string
	containerConfig *container.Config
	hostConfig      *container.HostConfig
}

// NewGoBuildRunner returns a new GoBuildRunner
func NewGoBuildRunner(packageName string) *GoBuildRunner {
	currentUser, _ := user.Current()
	repoRootCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	repoRootDir, err := repoRootCmd.Output()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get repo root dir")
	}
	gomodCacheDir := goModCacheDir(currentUser)
	goBuild := NewGoBuild()
	g := &GoBuildRunner{
		GoBuildImage: goBuild,
		DockerRunner: *NewDockerRunner(goBuild.Image()),
		packageName:  packageName,
		containerConfig: &container.Config{
			Image: goBuild.Image(),
			Env: []string{
				"GOCACHE=/go-cache",
				"GOPATH=/go",
				"GOARCH=" + runtime.GOARCH,
				"OS=" + runtime.GOOS,
				"GOOS=" + runtime.GOOS,
			},
			WorkingDir: "/go/src/" + packageName,
			Tty:        true,
		},
		hostConfig: &container.HostConfig{
			NetworkMode: "host",
			Binds: []string{
				fmt.Sprintf("%s:%s:rw", gomodCacheDir, modCacheDir),
				fmt.Sprintf("%s/.go-pkg-cache:%s:rw", repoRootDir, goCacheDir),
			},
		},
	}
	if currentUser.Uid == "0" {
		g.WithEnv("RUN_AS_ROOT='true'")
	} else {
		g.WithEnv("LOCAL_USER_ID=" + currentUser.Uid)
	}
	return g
}

// WithVersion sets the version for the go-build image in GoBuildRunner
func (g *GoBuildRunner) WithVersion(version string) *GoBuildRunner {
	g.imageVersion = version
	g.containerConfig.Image = g.Image()
	return g
}

func (g *GoBuildRunner) Version() string {
	return g.imageVersion
}

// WithEnv sets the environment variables for the container
func (g *GoBuildRunner) WithEnv(env ...string) *GoBuildRunner {
	g.containerConfig.Env = append(g.containerConfig.Env, env...)
	return g
}

func (g *GoBuildRunner) getBindMountSource(targetPath string) string {
	for _, mount := range g.hostConfig.Binds {
		parts := strings.Split(mount, ":")
		if len(parts) >= 2 && parts[1] == targetPath {
			return parts[0]
		}
	}
	return ""
}

func (g *GoBuildRunner) hasBind(bind string) bool {
	_parts := strings.Split(bind, ":")
	for _, mount := range g.hostConfig.Binds {
		parts := strings.Split(mount, ":")
		if len(parts) >= 2 && parts[0] == _parts[0] && parts[1] == _parts[1] {
			return true
		}
	}
	return false
}

func (g *GoBuildRunner) hasBindMount(targetPath string) bool {
	return g.getBindMountSource(targetPath) != ""
}

func (g *GoBuildRunner) removeBindMount(targetPath string) {
	source := g.getBindMountSource(targetPath)
	for i, mount := range g.hostConfig.Binds {
		parts := strings.Split(mount, ":")
		if len(parts) >= 2 && parts[1] == targetPath && parts[0] == source {
			g.hostConfig.Binds = append(g.hostConfig.Binds[:i], g.hostConfig.Binds[i+1:]...)
			return
		}
	}
}

// WithVolume sets the volume for the container
func (g *GoBuildRunner) WithVolume(volume ...string) *GoBuildRunner {
	for _, v := range volume {
		if g.hasBind(v) {
			logrus.WithField("volume", v).Fatal("volume already exists")
		}
		g.hostConfig.Binds = append(g.hostConfig.Binds, v)
	}
	return g
}

// WithRepoVolume sets the volume for the repository
func (g *GoBuildRunner) WithRepoVolume(volume string) *GoBuildRunner {
	g.repoVolume = volume
	g.WithVolume(g.repoVolume)
	return g
}

// WithBashCmd runs the command in the container using bash
func (g *GoBuildRunner) WithBashCmd(cmd string) *GoBuildRunner {
	g.containerConfig.Cmd = []string{"bash"}
	g.cmd = []string{"bash", "-c", cmd}
	return g
}

// WithBashCmd runs the command in the container using sh
func (g *GoBuildRunner) WithShCmd(cmd string) *GoBuildRunner {
	g.containerConfig.Cmd = []string{"sh"}
	g.cmd = []string{"sh", "-c", cmd}
	return g
}

// UsingGoModCache sets the volume for go mod cache
func (g *GoBuildRunner) UsingGoModCache(dir string) *GoBuildRunner {
	if g.hasBindMount(modCacheDir) {
		g.removeBindMount(modCacheDir)
	}
	g.WithVolume(fmt.Sprintf("%s:%s:rw", dir, modCacheDir))
	return g
}

func (g *GoBuildRunner) Run() {
	if g.packageName == "" {
		logrus.Fatal("package name is required")
	}
	if g.cmd == nil {
		logrus.Fatal("command is required")
	}
	if g.repoVolume == "" {
		logrus.Fatal("repository is required")
	}

	goModCache := g.getBindMountSource(modCacheDir)
	goPkgCache := g.getBindMountSource(goCacheDir)
	dirs := []string{"bin", goPkgCache, goModCache}
	for _, dir := range dirs {
		err := file.CreateDirIfNotExist(dir)
		if err != nil {
			logrus.WithError(err).Fatal("failed to create directory ", dir)
		}
	}

	g.PullImage()
	resp := g.RunContainer(g.containerConfig, g.hostConfig)
	defer g.RemoveContainer(resp.ID)
	inspect := g.ExecInContainer(resp.ID, g.cmd...)
	g.StopContainer(resp.ID)
	if inspect.ExitCode != 0 {
		logrus.WithFields(logrus.Fields{
			"cmd":      g.cmd,
			"exitCode": inspect.ExitCode,
		}).Fatal("executing failed")
	}
}

// goModCacheDir returns the directory for gopath
//
// If GOPATH is set and uses multiple paths,
// use the first path in GOPATH as that is the default used by go module.
func goModCacheDir(currentUser *user.User) string {
	dir := currentUser.HomeDir + modCacheDir
	if os.Getenv("GOPATH") != "" {
		gopaths := strings.Split(os.Getenv("GOPATH"), ":")
		dir = gopaths[0] + "/pkg/mod"
	}
	return dir
}
