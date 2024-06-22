package ctl

import (
	"github.com/projectcalico/fixham/internal/client"
	"github.com/projectcalico/fixham/internal/docker"
)

// Client is used to interact with the ctl package.
type Client = client.Client

// DockerRunner is used to interact with the docker package.
type DockerRunner = docker.DockerRunner

// GoBuildRunner is used to interact with the docker package using calico/go-build image.
type GoBuildRunner = docker.GoBuildRunner

// NewClient returns a new instance of the ctl client.
func NewClient(packageName string) *Client {
	return client.NewClient(packageName)
}

// NewDockerRunner returns a new instance of the DockerRunner.
func NewDockerRunner(image string) *DockerRunner {
	return docker.NewDockerRunner(image)
}

// NewGoBuildRunner returns a new instance of the GoBuildRunner.
func NewGoBuildRunner(packageName string) *GoBuildRunner {
	return docker.NewGoBuildRunner(packageName)
}
