package ctl

import (
	"github.com/projectcalico/ctl/internal/client"
	"github.com/projectcalico/ctl/internal/docker"
)

// Client is used to interact with the ctl package.
type Client = client.Client

// DockerRunner is used to interact with the docker package.
type DockerRunner = docker.DockerRunner

// NewClient returns a new instance of the ctl client.
func NewClient(packageName string) *Client {
	return client.NewClient(packageName)
}

func NewDockerRunner(image string) *DockerRunner {
	return docker.NewDockerRunner(image)
}
