package registry

import (
	"calico_postrelease/pkg/container"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"sync"
)

type GCRRegistry struct {
	ApiToken string
	HostName string
}

func NewGCRRegistry(hostname string) GCRRegistry {
	reg := GCRRegistry{
		ApiToken: "asdfasdf",
		HostName: hostname,
	}
	return reg
}

var mutex sync.Mutex
var cache2 = make(map[string][]string)

var setAccessToken sync.Once

// This function fetches the list of all existing tags from a given GCR host
// for a given image name. Note that we need to turn 'calico/cni' into 'cni'
// because everything on GCR is pushed to e.g. 'projectcalico-org/cni' instead,
// so we make that assumption here and just want ImageBaseName (the part after the
// first slash) for our own purposes.
func (reg GCRRegistry) GetImageTagsList(HostName string, ImageBaseName string) ([]string, error) {
	var gCloudAuthToken string
	client := &http.Client{}

	api_url := fmt.Sprintf("https://%s/v2/projectcalico-org/%s/tags/list", reg.HostName, ImageBaseName)
	req, err := http.NewRequest("GET", api_url, nil)
	if err != nil {
		return nil, fmt.Errorf("error! %v", err)
	}

	// setAccessToken is a sync.Once object; sync.Once.Do() will call the function
	// given one time only, and every other time it's a no-op. This ensures that
	// we don't re-generate access tokens more than once.
	setAccessToken.Do(func() {
		gCloudAuthTokenOutput, err := exec.Command("gcloud", "auth", "print-access-token").Output()
		if err != nil {
			panic(err)
		}
		gCloudAuthToken = strings.TrimSpace(string(gCloudAuthTokenOutput))
	})

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", gCloudAuthToken))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error! %v", err)
	}
	if resp.StatusCode != 200 {
		var body []byte
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		return nil, fmt.Errorf("got non-200 status code: %v: %v", resp.StatusCode, string(body))
	}

	var body []byte
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read JSON data from HTTP body: %s", err)
	}

	var data DockerV2APIResponse

	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal JSON data: %s", err)
	}

	return data.Tags, nil
}

func (reg GCRRegistry) CheckImageExists(Image container.Image) error {
	ImageBaseName, _ := strings.CutPrefix(Image.Name, "calico/")
	var cache_key = fmt.Sprintf("%s-%s", reg.HostName, ImageBaseName)
	var imageManifestTags []string

	// Lock our mutex so that we can make sure we're the only
	// ones actually fetching this result from the API
	mutex.Lock()
	if imageManifestTagsCache, ok := cache2[cache_key]; ok {
		imageManifestTags = imageManifestTagsCache
	} else {
		imageManifestResults, err := reg.GetImageTagsList(reg.HostName, ImageBaseName)
		if err != nil {
			return fmt.Errorf("unable to get tags: %v", err)
		}
		imageManifestTags = imageManifestResults
		cache2[cache_key] = imageManifestTags
	}
	// All done, unlock for the next test to run
	mutex.Unlock()

	if slices.Contains(imageManifestTags, Image.Tag) {
		return nil
	} else {
		return fmt.Errorf("tag %s not found on registry %s", Image.Tag, reg.HostName)
	}
}

func (reg GCRRegistry) CheckImageExistsOld(Image container.Image) error {
	ImageBaseName, _ := strings.CutPrefix(Image.Name, "calico/")
	var cache_key = fmt.Sprintf("%s-%s", reg.HostName, ImageBaseName)
	var imageManifestTags []string

	if imageManifestTagsCache, ok := cache2[cache_key]; ok {
		// fmt.Printf("Got value from cache key %s\n", cache_key)
		imageManifestTags = imageManifestTagsCache
	} else {
		client := &http.Client{}

		api_url := fmt.Sprintf("https://%s/v2/projectcalico-org/%s/tags/list", reg.HostName, ImageBaseName)
		req, err := http.NewRequest("GET", api_url, nil)
		if err != nil {
			return fmt.Errorf("error! %v", err)
		}

		gCloudAuthTokenOutput, err := exec.Command("gcloud", "auth", "print-access-token").Output()
		if err != nil {
			return fmt.Errorf("error getting gCloud auth token: %v", err)
		}

		gCloudAuthToken := strings.TrimSpace(string(gCloudAuthTokenOutput))

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(gCloudAuthToken)))
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("error! %v", err)
		}
		if resp.StatusCode != 200 {
			var body []byte
			body, err = io.ReadAll(resp.Body)
			if err != nil {
				panic(err)
			}
			return fmt.Errorf("got non-200 status code: %v: %v", resp.StatusCode, string(body))
		}

		var body []byte
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("unable to read JSON data from HTTP body: %s", err)
		}

		var data DockerV2APIResponse

		err = json.Unmarshal(body, &data)
		if err != nil {
			return fmt.Errorf("unable to unmarshal JSON data: %s", err)
		}

		imageManifestTags = data.Tags

		cache2[cache_key] = imageManifestTags

	}

	// fmt.Printf("Got value from API for %s\n", cache_key)
	if slices.Contains(imageManifestTags, Image.Tag) {
		return nil
	} else {
		return fmt.Errorf("tag %s not found on registry %s", Image.Tag, reg.HostName)
	}

}
