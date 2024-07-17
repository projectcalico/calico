package registry

import (
	"calico_postrelease/pkg/container"
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/patrickmn/go-cache"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/ref"
)

type Registry interface {
	CheckImageExists() error
}

type RegistryChecker struct {
	Cache    *cache.Cache
	Lock     *sync.Mutex
	Context  context.Context
	Registry regclient.RegClient
}

type DockerV2APIResponse struct {
	Child     []any                                     `json:"child"`
	Manifests map[string]DockerV2APIImageRepresentation `json:"manifest"`
	Name      string                                    `json:"name"`
	Tags      []string                                  `json:"tags"`
}
type DockerV2APIImageRepresentation struct {
	ImageSizeBytes string   `json:"imageSizeBytes"`
	LayerID        string   `json:"layerId"`
	MediaType      string   `json:"mediaType"`
	Tag            []string `json:"tag"`
	TimeCreatedMs  string   `json:"timeCreatedMs"`
	TimeUploadedMs string   `json:"timeUploadedMs"`
}

func New() (RegistryChecker, error) {
	reg := RegistryChecker{}
	reg.Cache = cache.New(cache.NoExpiration, cache.NoExpiration)
	reg.Context = context.Background()
	reg.Registry = *regclient.New()

	var lock = sync.Mutex{}
	reg.Lock = &lock

	reg.Cache.Add("CacheHit", 0, cache.NoExpiration)
	reg.Cache.Add("CacheMiss", 0, cache.NoExpiration)

	return reg, nil
}

func (reg RegistryChecker) fetchImageTagInfo(ImageName string) ([]string, error) {
	imageRef, err := ref.New(ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to create ref: %w", err)
	}
	defer reg.Registry.Close(reg.Context, imageRef)

	// get a manifest (or call other regclient methods)
	TagList, err := reg.Registry.TagList(reg.Context, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}

	return TagList.Tags, nil
}

func (reg RegistryChecker) CheckImageTagExists(ContainerImage container.Image) error {
	reg.Lock.Lock()
	var TagList []string

	var ImagePath = ContainerImage.FullPath()

	if x, found := reg.Cache.Get(ImagePath); found {
		reg.Cache.IncrementInt("CacheHit", 1)
		// fmt.Println("Got image data from cache")
		TagList = x.([]string)
	} else {
		reg.Cache.IncrementInt("CacheMiss", 1)
		// fmt.Printf("Getting image data from server for %s", ContainerImage.FullPath())
		x, err := reg.fetchImageTagInfo(ImagePath)
		if err != nil {
			return fmt.Errorf("failed to fetch image tag info: %w", err)
		}
		TagList = x
		reg.Cache.Add(ImagePath, TagList, cache.NoExpiration)
	}
	reg.Lock.Unlock()

	if slices.Contains(TagList, ContainerImage.Tag) {
		return nil
	} else {
		return fmt.Errorf("tag %s not found in tag list for %s", ContainerImage.Tag, ImagePath)
	}
}

// func validateImages() {
// 	ctx := context.Background()
// 	rc := regclient.New()

// 	// create a reference for an image
// 	r, err := ref.New("asia.gcr.io/projectcalico-org/pod2daemon-flexvol")
// 	if err != nil {
// 		fmt.Printf("failed to create ref: %v\n", err)
// 		return
// 	}
// 	defer rc.Close(ctx, r)
// 	// get a manifest (or call other regclient methods)
// 	m, err := rc.TagList(ctx, r)
// 	if err != nil {
// 		fmt.Printf("failed to get manifest: %v\n", err)
// 		return
// 	}

// 	fmt.Println(slices.Contains(m.Tags, "v3.28.0"))

// }
