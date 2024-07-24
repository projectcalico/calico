package container

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type Image struct {
	HostName string
	Name     string
	Tag      string
}

func (i Image) FullPath() string {
	var registryPath string

	if strings.HasSuffix(i.HostName, "gcr.io") {
		registryPath = "projectcalico-org"
	} else {
		registryPath = "calico"
	}

	return fmt.Sprintf("%s/%s/%s", i.HostName, registryPath, i.Name)
}

func (i Image) FullPathWithTag() string {
	return fmt.Sprintf("%s:%s", i.FullPath(), i.Tag)
}

func (i Image) NameWithTag() string {
	return fmt.Sprintf("%s:%s", i.Name, i.Tag)
}

func (i Image) GetManifest() string {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}
	containers, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		panic(err)
	}

	for _, ctr := range containers {
		fmt.Printf("%s %s\n", ctr.ID, ctr.Image)
	}
	return "food"
}
