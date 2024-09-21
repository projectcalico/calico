package registry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

// TagsResponse is a struct for the response from the docker registry API for tags
type TagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// DockerRunner is a struct for running docker commands
type DockerRunner struct {
	dockerClient *client.Client
}

// ManifestList represents a Docker Manifest List
type ManifestList struct {
	SchemaVersion int                               `json:"schemaVersion"`
	MediaType     string                            `json:"mediaType"`
	Manifests     []manifestlist.ManifestDescriptor `json:"manifests"`
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
func (d *DockerRunner) PullImage(img string) error {
	logrus.WithField("image", img).Debug("Checking if image exists")
	imageSummary, err := d.dockerClient.ImageList(context.Background(), image.ListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", img)),
	})
	if err != nil {
		logrus.WithError(err).Error("failed to list images")
		return err
	}
	if len(imageSummary) == 0 {
		logrus.WithField("image", img).Debug("Image does not exist, pulling...")
		reader, err := d.dockerClient.ImagePull(context.Background(), img, image.PullOptions{})
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

// TagImage tags the image with the new tag
func (d *DockerRunner) TagImage(currentTag, newTag string) error {
	logrus.WithFields(logrus.Fields{
		"currentTag": currentTag,
		"newTag":     newTag,
	}).Debug("Tagging image")
	if err := d.dockerClient.ImageTag(context.Background(), currentTag, newTag); err != nil {
		logrus.WithError(err).Error("failed to tag image")
		return err
	}
	return nil
}

type errorMessage struct {
	Error string
}

// PushImage pushes the image to the registry
func (d *DockerRunner) PushImage(img string) error {
	logrus.WithField("image", img).Debug("Pushing image")
	registryAuth, err := registryAuthStr(ParseImage(img).Registry())
	if err != nil {
		logrus.WithError(err).Error("failed to get registry auth")
		return err
	}
	reader, err := d.dockerClient.ImagePush(context.Background(), img, image.PushOptions{
		RegistryAuth: registryAuth,
	})
	if err != nil {
		logrus.WithField("image", img).WithError(err).Error("failed to push image")
		return err
	}
	defer reader.Close()
	var errorMessage errorMessage
	buffIOReader := bufio.NewReader(reader)
	for {
		stream, err := buffIOReader.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err := json.Unmarshal(stream, &errorMessage); err != nil {
			logrus.WithError(err).Error("failed to unmarshal push response")
			return err
		}
		if errorMessage.Error != "" {
			logrus.WithField("error", errorMessage).Error("failed to push image")
			return fmt.Errorf("%s", errorMessage.Error)
		}
	}
	logrus.WithField("image", img).Debug("Image pushed")
	return nil
}

// RemoveImage removes the image if it exists
func (d *DockerRunner) RemoveImage(img string) error {
	logrus.WithField("image", img).Debug("Checking if image exists")
	images, err := d.dockerClient.ImageList(context.Background(), image.ListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", img)),
	})
	if err != nil {
		logrus.WithError(err).Error("failed to list images")
		return err
	}
	if len(images) == 0 {
		logrus.Debug(img, " image does not exist")
		return nil
	}

	for _, img := range images {
		logrus.WithField("image", img.ID).Debug("Removing image")
		_, err := d.dockerClient.ImageRemove(context.Background(), img.ID, image.RemoveOptions{
			Force:         true,
			PruneChildren: true,
		})
		if err != nil {
			logrus.WithField("image", img.ID).WithError(err).Error("failed to remove image")
			return err
		}
		logrus.WithField("image", img.ID).Debug("Image removed")
	}
	return nil
}

// ManifestPush pushes the manifest list to the registry.
//
// Since "docker manifest create/push" is considered experimental, it is not supported in the docker client library.
// As a workaround, we can use the docker command to create and push the manifest list.
func (d *DockerRunner) ManifestPush(manifestListName string, images []string) error {
	createArgs := []string{"manifest", "create", "--amend", manifestListName}
	createArgs = append(createArgs, images...)
	if _, err := command.Run("docker", createArgs); err != nil {
		logrus.WithError(err).Error("failed to create manifest list")
		return err
	}
	if _, err := command.Run("docker", []string{"manifest", "push", manifestListName}); err != nil {
		logrus.WithError(err).Error("failed to push manifest list")
		return err
	}
	return nil
}

// RunContainer runs a container with the given config and host config
func (d *DockerRunner) RunContainer(containerConfig *container.Config, hostConfig *container.HostConfig) (container.CreateResponse, error) {
	logrus.WithField("image", containerConfig.Image).Debug("Creating container")
	response, err := d.dockerClient.ContainerCreate(context.Background(), containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		logrus.WithError(err).Error("failed to create container")
		return container.CreateResponse{}, err
	}

	logrus.WithField("containerID", response.ID).Debug("Starting container ", response.ID)
	if err := d.dockerClient.ContainerStart(context.Background(), response.ID, container.StartOptions{}); err != nil {
		logrus.WithField("containerID", response.ID).WithError(err).Error("failed to start container")
		return container.CreateResponse{}, err
	}
	return response, nil
}

// ExecInContainer executes a command in the container
func (d *DockerRunner) ExecInContainer(containerID string, cmd ...string) (container.ExecInspect, error) {
	logrus.WithFields(logrus.Fields{
		"containerID": containerID,
		"cmd":         cmd,
	}).Debug("Creating exec instance")
	exec, err := d.dockerClient.ContainerExecCreate(context.Background(), containerID, container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
	})
	if err != nil {
		logrus.WithError(err).Error("failed to create exec instance")
		return container.ExecInspect{}, err
	}

	logrus.WithFields(logrus.Fields{
		"containerID": containerID,
		"execID":      exec.ID,
	}).Debug("Attach to the exec instance")
	resp, err := d.dockerClient.ContainerExecAttach(context.Background(), exec.ID, container.ExecAttachOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to start exec instance")
	}
	defer resp.Close()

	output, err := io.ReadAll(resp.Reader)
	if err != nil {
		logrus.WithError(err).Error("failed to read exec output")
		return container.ExecInspect{}, err
	}

	logrus.WithField("cmd", cmd).Infof("printing output...\n%s\n...end of output", string(output))

	inspect, err := d.dockerClient.ContainerExecInspect(context.Background(), exec.ID)
	if err != nil {
		logrus.WithError(err).Error("failed to inspect exec instance")
		return container.ExecInspect{}, err
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
