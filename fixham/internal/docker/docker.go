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

// DockerRunner is a struct for running docker commands
type DockerRunner struct {
	dockerClient *client.Client
}

// NewDockerRunner returns a new DockerRunner
func NewDockerRunner() (d *DockerRunner, err error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logrus.WithError(err).Error("failed to create docker client")
		return nil, err
	}
	return &DockerRunner{
		dockerClient: dockerClient,
	}, nil
}

// MustDockerRunner returns a new DockerRunner or exits the program
func MustDockerRunner() *DockerRunner {
	d, err := NewDockerRunner()
	if err != nil {
		logrus.WithError(err).Fatal("failed to create docker runner")
	}
	return d
}

// PullImage pulls the image if it does not exist
func (d *DockerRunner) PullImage(image string) error {
	logrus.Debug("Checking if ", image, " image exists")
	imageSummary, err := d.dockerClient.ImageList(context.Background(), types.ImageListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", image)),
	})
	if err != nil {
		logrus.WithError(err).Error("failed to list images")
		return err
	}
	if len(imageSummary) == 0 {
		logrus.Debug("Pulling ", image, " image")
		reader, err := d.dockerClient.ImagePull(context.Background(), image, types.ImagePullOptions{})
		if err != nil {
			logrus.WithError(err).Error("failed to pull image")
			return err
		}
		defer reader.Close()
		if _, err := io.Copy(os.Stdout, reader); err != nil {
			logrus.WithError(err).Error("failed to copy image pull output")
			return err
		}
	}
	return nil
}

// RemoveImage removes the image if it exists
func (d *DockerRunner) RemoveImage(image string) error {
	logrus.Debug("Checking if ", image, " image exists")
	images, err := d.dockerClient.ImageList(context.Background(), types.ImageListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", image)),
	})
	if err != nil {
		logrus.WithError(err).Error("failed to list images")
		return err
	}
	if len(images) == 0 {
		logrus.Debug(image, " image does not exist")
		return nil
	}

	for _, image := range images {
		logrus.WithField("image", image.ID).Debug("Removing image")
		_, err := d.dockerClient.ImageRemove(context.Background(), image.ID, types.ImageRemoveOptions{
			Force:         true,
			PruneChildren: true,
		})
		if err != nil {
			logrus.WithField("image", image.ID).WithError(err).Error("failed to remove image")
			return err
		}
		logrus.WithField("image", image.ID).Debug("Image removed")
	}
	return nil
}

// RunContainer runs a container with the given config and host config
func (d *DockerRunner) RunContainer(containerConfig *container.Config, hostConfig *container.HostConfig) (container.CreateResponse, error) {
	logrus.Debug("Creating container")
	response, err := d.dockerClient.ContainerCreate(context.Background(), containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		logrus.WithError(err).Error("failed to create container")
		return container.CreateResponse{}, err
	}

	logrus.Debug("Starting container ", response.ID)
	if err := d.dockerClient.ContainerStart(context.Background(), response.ID, container.StartOptions{}); err != nil {
		logrus.WithField("containerID", response.ID).WithError(err).Error("failed to start container")
		return container.CreateResponse{}, err
	}
	return response, nil
}

// ExecInContainer executes a command in the container
func (d *DockerRunner) ExecInContainer(containerID string, cmd ...string) (types.ContainerExecInspect, error) {
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
		logrus.WithError(err).Error("failed to create exec instance")
		return types.ContainerExecInspect{}, err
	}

	logrus.Debug("Attach to the exec instance")
	resp, err := d.dockerClient.ContainerExecAttach(context.Background(), exec.ID, types.ExecStartCheck{})
	if err != nil {
		logrus.WithError(err).Error("failed to start exec instance")
	}
	defer resp.Close()

	output, err := io.ReadAll(resp.Reader)
	if err != nil {
		logrus.WithError(err).Error("failed to read exec output")
		return types.ContainerExecInspect{}, err
	}

	logrus.WithField("cmd", cmd).Print("printing output...\n", string(output), "\n...end of output")

	inspect, err := d.dockerClient.ContainerExecInspect(context.Background(), exec.ID)
	if err != nil {
		logrus.WithError(err).Error("failed to inspect exec instance")
		return types.ContainerExecInspect{}, err
	}
	return inspect, nil
}

// StopContainer stops the container
func (d *DockerRunner) StopContainer(containerID string) error {
	if err := d.dockerClient.ContainerStop(context.Background(), containerID, container.StopOptions{}); err != nil {
		logrus.WithError(err).Error("failed to stop container")
		return err
	}
	return nil
}

// RemoveContainer removes the container
func (d *DockerRunner) RemoveContainer(containerID string) error {
	if err := d.dockerClient.ContainerRemove(context.Background(), containerID, container.RemoveOptions{}); err != nil {
		logrus.WithError(err).Error("failed to remove container")
		return err
	}
	return nil
}
