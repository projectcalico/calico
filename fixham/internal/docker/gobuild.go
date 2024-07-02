package docker

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

const (
	modCacheDir             = "/go/pkg/mod"
	goCacheDir              = "/go-cache"
	defaultGoBuildImageName = "calico/go-build"
)

// GoBuildImage is the struct for the go-build image
// i.e calico/go-build:<version>
type GoBuildImage struct {
	imageName    string
	imageVersion string
}

// NewGoBuild returns a new GoBuildImage
// with default image name and version
func NewGoBuild(name string, version string) GoBuildImage {
	if name == "" {
		logrus.Fatal("name of the go-build image is required i.e. calico/go-build")
	}
	if version == "" {
		logrus.Fatal("version of the go-build image is required i.e. latest")
	}
	return GoBuildImage{
		imageName:    name,
		imageVersion: version,
	}
}

// Image returns the image name and version
// i.e "calico/go-build:<version>"
func (g GoBuildImage) Image() string {
	return fmt.Sprintf("%s:%s", g.imageName, g.imageVersion)
}

// Version returns the version of the go-build image
func (g GoBuildImage) Version() string {
	return g.imageVersion
}

// GoBuildRunner is the struct for running go-build image
// for a specific package name
type GoBuildRunner struct {
	GoBuildImage
	DockerRunner
	packageName     string
	containerConfig *container.Config
	hostConfig      *container.HostConfig
}

// NewGoBuildRunner returns a new GoBuildRunner
// with the given name, version, package name, working directory and repo root directorys
func NewGoBuildRunner(name, version, packageName, wd, repoRootDir string) (g *GoBuildRunner, err error) {
	currentUser, _ := user.Current()
	gomodCacheDir := goModCacheDir(currentUser)
	goBuild := NewGoBuild(name, version)
	dockerRunner := MustDockerRunner()
	g = &GoBuildRunner{
		GoBuildImage: goBuild,
		DockerRunner: *dockerRunner,
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
				fmt.Sprintf("%s:/go/src/%s:rw", wd, packageName),
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
	return g, nil
}

// MustGoBuildRunner returns a new GoBuildRunner
func MustGoBuildRunner(name, version, packageName, wd string, repoRootDir string) *GoBuildRunner {
	g, err := NewGoBuildRunner(name, version, packageName, wd, repoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create GoBuildRunner")
	}
	return g
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

// WithVolume sets the volume for the container
func (g *GoBuildRunner) WithVolume(volume ...string) (runner *GoBuildRunner, err error) {
	for _, v := range volume {
		if g.hasBind(v) {
			logrus.WithField("volume", v).Error("volume already exists")
			return g, fmt.Errorf("volume already exists")
		}
		g.hostConfig.Binds = append(g.hostConfig.Binds, v)
	}
	return g, nil
}

func (g *GoBuildRunner) RunBashCmd(cmd string) error {
	bashCmd := []string{"bash"}
	g.containerConfig.Cmd = bashCmd
	return g.Run(append(bashCmd, "-c", cmd))
}

func (g *GoBuildRunner) RunShCmd(cmd string) error {
	shCmd := []string{"sh"}
	g.containerConfig.Cmd = shCmd
	return g.Run(append(shCmd, "-c", cmd))
}

func (g *GoBuildRunner) Run(cmd []string) error {
	if g.imageName == defaultGoBuildImageName {
		// TODO: Check if the version is the latest
	} else {
		logrus.Warn("Using non-default go-build image ", g.imageName)
	}
	goModCache := g.getBindMountSource(modCacheDir)
	goPkgCache := g.getBindMountSource(goCacheDir)
	dirs := []string{"bin", goPkgCache, goModCache}
	for _, dir := range dirs {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			logrus.WithError(err).Fatal("failed to create directory ", dir)
			return err
		}
	}

	err := g.PullImage(g.Image())
	if err != nil {
		logrus.WithError(err).Error("failed to pull image")
		return err
	}
	resp, err := g.RunContainer(g.containerConfig, g.hostConfig)
	if err != nil {
		logrus.WithError(err).Error("failed to run container")
		return err
	}
	inspect, err := g.ExecInContainer(resp.ID, cmd...)
	if err != nil {
		logrus.WithField("cmd", cmd).Error("executing failed")
		return err
	}
	err = g.StopContainer(resp.ID)
	if err != nil {
		logrus.WithError(err).Error("failed to stop container")
	} else {
		_ = g.RemoveContainer(resp.ID)
	}

	if inspect.ExitCode != 0 {
		return fmt.Errorf("command failed with exit code %d", inspect.ExitCode)
	}
	return nil
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
