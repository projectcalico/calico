package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/ctl/file"
)

func goModCacheDir(currentUser *user.User) string {
	if os.Getenv("GOPATH") == "" {
		return fmt.Sprintf("%s/go/pkg/mod", currentUser.HomeDir)
	} else {
		gopaths := strings.Split(os.Getenv("GOPATH"), ":")
		return fmt.Sprintf("%s/pkg/mod", gopaths[0])
	}
}

func DockerGoBuild(image string, cmd string, packageName string) {
	currentDir, _ := os.Getwd()
	currentUser, _ := user.Current()
	goModCache := goModCacheDir(currentUser)
	dirs := []string{"bin", ".go-pkg-cache", goModCache}
	for _, dir := range dirs {
		err := file.CreateDirIfNotExist(dir)
		if err != nil {
			logrus.WithError(err).Fatal("failed to create directory ", dir)
		}
	}
	envs := []string{
		fmt.Sprintf("LOCAL_USER_ID=%s", currentUser.Uid),
		"GOCACHE=/go-cache",
		"GOPATH=/go",
		fmt.Sprintf("GOARCH=%s", runtime.GOARCH),
		fmt.Sprintf("OS=%s", runtime.GOOS),
		fmt.Sprintf("GOOS=%s", runtime.GOOS),
	}
	volumes := []string{
		fmt.Sprintf("%s:/go/pkg/mod:rw", goModCache),
		fmt.Sprintf("%s:/go/src/%s:rw", currentDir, packageName),
		fmt.Sprintf("%s/.go-pkg-cache:/go-cache:rw", currentDir),
	}
	if currentUser.Uid == "0" {
		envs = append(envs, "RUN_AS_ROOT='true'")
	}
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock != "" {
		volumes = append(volumes, fmt.Sprintf("%s:/ssh-agent", sshAuthSock))
		envs = append(envs, "SSH_AUTH_SOCK=/ssh-agent")
	}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logrus.WithError(err).Fatal("failed to create docker client")
	}

	logrus.Debug("Checking if ", image, " image exists")
	imageSummary, err := cli.ImageList(context.Background(), types.ImageListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", image)),
	})
	if err != nil {
		logrus.WithError(err).Fatal("failed to list images")
	}
	if len(imageSummary) == 0 {
		logrus.Debug("Pulling ", image, " image")
		reader, err := cli.ImagePull(context.Background(), image, types.ImagePullOptions{})
		if err != nil {
			logrus.WithError(err).Fatal("failed to pull image")
		}
		defer reader.Close()
		if _, err := io.Copy(os.Stdout, reader); err != nil {
			logrus.WithError(err).Fatal("failed to copy image pull output")
		}
	}

	logrus.Debug("Creating container")
	response, err := cli.ContainerCreate(context.Background(), &container.Config{
		Image:      image,
		Env:        envs,
		Cmd:        []string{"bash"},
		WorkingDir: fmt.Sprintf("/go/src/%s", packageName),
		Tty:        true,
	}, &container.HostConfig{
		NetworkMode: "host",
		Binds:       volumes,
	}, nil, nil, "")
	if err != nil {
		logrus.WithError(err).Fatal("failed to create container")
	}

	logrus.Debug("Starting container")
	if err := cli.ContainerStart(context.Background(), response.ID, container.StartOptions{}); err != nil {
		logrus.WithError(err).Fatal("failed to start container")
	}

	logrus.Debug("Create exec instance")
	logrus.WithField("cmd", cmd).Info("executing in container...")
	exec, err := cli.ContainerExecCreate(context.Background(), response.ID, types.ExecConfig{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          []string{"bash", "-c", cmd},
	})
	if err != nil {
		logrus.WithError(err).Fatal("failed to create exec instance")
	}

	logrus.Debug("Attach to the exec instance")
	resp, err := cli.ContainerExecAttach(context.Background(), exec.ID, types.ExecStartCheck{})
	if err != nil {
		logrus.WithError(err).Fatal("failed to start exec instance")
	}
	defer resp.Close()

	output, err := io.ReadAll(resp.Reader)
	if err != nil {
		logrus.WithError(err).Fatal("failed to read exec output")
	}
	logrus.WithField("cmd", cmd).Print("printing output...\n", string(output), "\n...end of output")
	inspectResponse, err := cli.ContainerExecInspect(context.Background(), exec.ID)
	if err != nil {
		logrus.WithError(err).Fatal("failed to inspect exec instance")
	}

	if err := cli.ContainerStop(context.Background(), response.ID, container.StopOptions{}); err != nil {
		logrus.WithError(err).Fatal("failed to stop container")
	}

	if err := cli.ContainerRemove(context.Background(), response.ID, container.RemoveOptions{}); err != nil {
		logrus.WithError(err).Fatal("failed to remove container")
	}

	if inspectResponse.ExitCode != 0 {
		logrus.WithFields(logrus.Fields{
			"cmd":      cmd,
			"exitCode": inspectResponse.ExitCode,
		}).Fatal("executing failed")
	}
}
