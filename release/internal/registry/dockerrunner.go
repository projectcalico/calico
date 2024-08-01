package registry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

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

type errorMessage struct {
	Error string
}

// PushImage pushes the image to the registry
func (d *DockerRunner) PushImage(img string, accessAuth string) error {
	logrus.WithField("image", img).Debug("Pushing image")
	registryAuth, err := registryAuthStr(accessAuth, ParseImage(img).Registry())
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
			return fmt.Errorf(errorMessage.Error)
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

// ManifestPush pushes the manifest list to the registry
func (d *DockerRunner) ManifestPush(manifestListName string, images []string, accessAuth string) error {
	logrus.WithField("manifest", manifestListName).Info("Creating manifest list")
	var manifests []manifestlist.ManifestDescriptor
	for _, img := range images {
		inspect, _, err := d.dockerClient.ImageInspectWithRaw(context.Background(), img)
		if err != nil {
			logrus.WithField("image", img).WithError(err).Error("failed to inspect image")
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
	}

	manifestList := manifestlist.ManifestList{
		Versioned: manifestlist.SchemaVersion,
		Manifests: manifests,
	}
	manifestListBytes, err := json.Marshal(manifestList)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal manifest list")
		return err
	}
	logrus.WithField("manifest", manifestListName).WithField("body", string(manifestListBytes)).Debug("Pushing manifest list")
	img := ParseImage(manifestListName)
	registryURL := img.Registry().ManifestURL(img)
	req, err := http.NewRequest(http.MethodPut, registryURL, bytes.NewReader(manifestListBytes))
	if err != nil {
		logrus.WithError(err).Error("failed to create request")
		return err
	}
	var token string
	scope := fmt.Sprintf("repository:%s:pull,push", img.Repository())
	if accessAuth == "" {
		token, err = getBearerTokenWithDefaultAuth(img.Registry(), scope)
	} else {
		token, err = getBearerTokenWithAuth(accessAuth, img.Registry(), scope)
	}
	if err != nil {
		logrus.WithError(err).Error("failed to get bearer token")
		return err
	}
	req.Header.Set("Content-Type", manifestlist.MediaTypeManifestList)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logrus.WithError(err).Error("failed to push manifest list")
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		logrus.WithFields(logrus.Fields{
			"status":   res.Status,
			"manifest": manifestListName,
		}).Error("failed to push manifest list")
		return fmt.Errorf("failed to push manifest list: %s", string(body))
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
