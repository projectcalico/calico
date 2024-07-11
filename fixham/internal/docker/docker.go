package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/manifest/schema2"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
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

// PushImage pushes the image to the registry
func (d *DockerRunner) PushImage(img string) error {
	logrus.WithField("image", img).Debug("Pushing image")
	reader, err := d.dockerClient.ImagePush(context.Background(), img, image.PushOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to push image")
		return err
	}
	defer reader.Close()
	if _, err := io.Copy(os.Stdout, reader); err != nil {
		logrus.WithError(err).Error("failed to copy image push output")
		return err
	}
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

func getRegistryURL(cli *client.Client) (string, error) {
	info, err := cli.Info(context.Background())
	if err != nil {
		return "", err
	}
	return info.RegistryConfig.IndexConfigs["docker.io"].Mirrors[0], nil
}

func getRepository(imageName string) string {
	parts := strings.Split(imageName, ":")
	return parts[0]
}

func getTag(imageName string) string {
	parts := strings.Split(imageName, ":")
	if len(parts) > 1 {
		return parts[1]
	}
	return "latest"
}

func (d *DockerRunner) ManifestCreate(manifestListName string, images ...string) error {
	logrus.WithField("manifest list", manifestListName).Debug("Creating manifest list")
	var manifests []manifestlist.ManifestDescriptor
	for _, img := range images {
		inspect, _, err := d.dockerClient.ImageInspectWithRaw(context.Background(), img)
		if err != nil {
			logrus.WithField("img", img).WithError(err).Error("failed to inspect image")
			return err
		}
		manifests = append(manifests, manifestlist.ManifestDescriptor{
			Platform: manifestlist.PlatformSpec{
				Architecture: inspect.Architecture,
				OS:           inspect.Os,
			},
			Descriptor: distribution.Descriptor{
				MediaType: schema2.MediaTypeManifest,
				Size:      inspect.Size,
				Digest:    digest.Digest(inspect.ID),
			},
		})

		manifestList := ManifestList{
			SchemaVersion: 2,
			MediaType:     manifestlist.MediaTypeManifestList,
			Manifests:     manifests,
		}
		body, err := json.Marshal(manifestList)
		if err != nil {
			logrus.WithError(err).Error("failed to marshal manifest list")
			return err
		}
		registryURL, err := getRegistryURL(d.dockerClient)
		if err != nil {
			logrus.WithError(err).Error("failed to get registry URL")
			return err
		}
		url := registryURL + "/v2/" + getRepository(manifestListName) + "/manifests/" + getTag(manifestListName)
		req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
		if err != nil {
			logrus.WithError(err).Error("failed to create request")
			return err
		}
		req.Header.Set("Content-Type", manifestlist.MediaTypeManifestList)
		resp, err := d.dockerClient.HTTPClient().Do(req)
		if err != nil {
			logrus.WithError(err).Error("failed to send request")
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			logrus.WithField("status", resp.Status).Error("failed to create manifest list")
			return err
		}
	}
	return nil
}

func (d *DockerRunner) ManifestPush(manifestListName string, images []string, purge bool) error {
	if err := d.ManifestCreate(manifestListName, images...); err != nil {
		logrus.WithError(err).Error("Failed to create manifest list")
		return err
	}
	if purge {
		if _, err := d.dockerClient.ImageRemove(context.Background(), manifestListName, image.RemoveOptions{
			Force: true,
		}); err != nil {
			logrus.WithError(err).Error("Failed to remove manifest list")
			return err
		}
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
