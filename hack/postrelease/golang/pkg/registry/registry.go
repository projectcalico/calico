// Package registry contains helper functionality for interacting with docker registries
package registry

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/patrickmn/go-cache"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/ref"

	"github.com/projectcalico/calico/hack/postrelease/golang/pkg/container"
)

// Checker manages references to registries and caches API results
type Checker struct {
	Cache    *cache.Cache
	Lock     *sync.Mutex
	Context  context.Context
	Registry regclient.RegClient
}

// New creates and configures a RegistryChecker instance
func New() (Checker, error) {
	reg := Checker{}
	reg.Cache = cache.New(cache.NoExpiration, cache.NoExpiration)
	reg.Context = context.Background()
	reg.Registry = *regclient.New()

	lock := sync.Mutex{}
	reg.Lock = &lock

	reg.Cache.Add("CacheHit", 0, cache.NoExpiration)
	reg.Cache.Add("CacheMiss", 0, cache.NoExpiration)

	return reg, nil
}

func (reg Checker) fetchImageTagInfo(ImageName string) ([]string, error) {
	imageRef, err := ref.New(ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to create ref: %w", err)
	}
	// defer reg.Registry.Close(reg.Context, imageRef)

	// get a manifest (or call other regclient methods)
	TagList, err := reg.Registry.TagList(reg.Context, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}

	return TagList.Tags, nil
}

// CheckImageTagExists validates that the image tag exists, fetching and caching image data if necessary
func (reg Checker) CheckImageTagExists(ContainerImage container.Image) error {
	reg.Lock.Lock()
	var TagList []string

	ImagePath := ContainerImage.FullPath()

	if x, found := reg.Cache.Get(ImagePath); found {
		reg.Cache.IncrementInt("CacheHit", 1)
		TagList = x.([]string)
	} else {
		reg.Cache.IncrementInt("CacheMiss", 1)
		x, err := reg.fetchImageTagInfo(ImagePath)
		if err != nil {
			errmsg := fmt.Sprintf("failed to fetch image tag info for %s", ImagePath)
			return fmt.Errorf("%s: %w", errmsg, err)
		}
		TagList = x
		reg.Cache.Add(ImagePath, TagList, cache.NoExpiration)
	}
	reg.Lock.Unlock()

	if slices.Contains(TagList, ContainerImage.Tag) {
		return nil
	}
	errmsg := fmt.Sprintf("tag %s not found in tag list for %s", ContainerImage.Tag, ImagePath)
	return fmt.Errorf(errmsg)
}
