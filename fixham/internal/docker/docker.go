package docker

import (
	"context"
	"io"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

type DockerRunner struct {
	dockerClient *client.Client
	image        string
}

func NewDockerRunner(image string) *DockerRunner {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logrus.WithError(err).Fatal("failed to create docker client")
	}
	return &DockerRunner{
		dockerClient: dockerClient,
		image:        image,
	}
}

func (d *DockerRunner) PullImage() {
	if d.image == "" {
		logrus.Fatal("image is not set")
	}
	logrus.Debug("Checking if ", d.image, " image exists")
	imageSummary, err := d.dockerClient.ImageList(context.Background(), types.ImageListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", d.image)),
	})
	if err != nil {
		logrus.WithError(err).Fatal("failed to list images")
	}
	if len(imageSummary) == 0 {
		logrus.Debug("Pulling ", d.image, " image")
		reader, err := d.dockerClient.ImagePull(context.Background(), d.image, types.ImagePullOptions{})
		if err != nil {
			logrus.WithError(err).Fatal("failed to pull image")
		}
		defer reader.Close()
		if _, err := io.Copy(os.Stdout, reader); err != nil {
			logrus.WithError(err).Fatal("failed to copy image pull output")
		}
	}
}

func (d *DockerRunner) RemoveImage() {
	if d.image == "" {
		logrus.Fatal("image is not set")
	}
	logrus.Debug("Checking if ", d.image, " image exists")
	images, err := d.dockerClient.ImageList(context.Background(), types.ImageListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", d.image)),
	})
	if err != nil {
		logrus.WithError(err).Fatal("failed to list images")
	}
	if len(images) == 0 {
		logrus.Debug(d.image, " image does not exist")
		return
	}

	for _, image := range images {
		logrus.WithField("image", image.ID).Debug("Removing image")
		_, err := d.dockerClient.ImageRemove(context.Background(), image.ID, types.ImageRemoveOptions{
			Force:         true,
			PruneChildren: true,
		})
		if err != nil {
			logrus.WithField("image", image.ID).WithError(err).Fatal("failed to remove image")
		}
		logrus.WithField("image", image.ID).Debug("Image removed")
	}
}

func (d *DockerRunner) RunContainer(containerConfig *container.Config, hostConfig *container.HostConfig) container.CreateResponse {
	logrus.Debug("Creating container")
	response, err := d.dockerClient.ContainerCreate(context.Background(), containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		logrus.WithError(err).Fatal("failed to create container")
	}

	logrus.Debug("Starting container ", response.ID)
	if err := d.dockerClient.ContainerStart(context.Background(), response.ID, container.StartOptions{}); err != nil {
		logrus.WithField("containerID", response.ID).WithError(err).Fatal("failed to start container")
	}
	return response
}

func (d *DockerRunner) ExecInContainer(containerID string, cmd ...string) types.ContainerExecInspect {
	logrus.Debug("Create exec instance")
	logrus.WithFields(logrus.Fields{
		"containerID": containerID,
		"cmd":         cmd,
	}).Info("executing in container...")
	exec, err := d.dockerClient.ContainerExecCreate(context.Background(), containerID, types.ExecConfig{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
	})
	if err != nil {
		logrus.WithError(err).Fatal("failed to create exec instance")
	}

	logrus.Debug("Attach to the exec instance")
	resp, err := d.dockerClient.ContainerExecAttach(context.Background(), exec.ID, types.ExecStartCheck{})
	if err != nil {
		logrus.WithError(err).Fatal("failed to start exec instance")
	}
	defer resp.Close()

	output, err := io.ReadAll(resp.Reader)
	if err != nil {
		logrus.WithError(err).Fatal("failed to read exec output")
	}

	logrus.WithField("cmd", cmd).Print("printing output...\n", string(output), "\n...end of output")

	inspect, err := d.dockerClient.ContainerExecInspect(context.Background(), exec.ID)
	if err != nil {
		logrus.WithError(err).Fatal("failed to inspect exec instance")
	}
	return inspect
}

func (d *DockerRunner) StopContainer(containerID string) {
	if err := d.dockerClient.ContainerStop(context.Background(), containerID, container.StopOptions{}); err != nil {
		logrus.WithError(err).Fatal("failed to stop container")
	}
}

func (d *DockerRunner) RemoveContainer(containerID string) {
	if err := d.dockerClient.ContainerRemove(context.Background(), containerID, container.RemoveOptions{}); err != nil {
		logrus.WithError(err).Fatal("failed to remove container")
	}
}
