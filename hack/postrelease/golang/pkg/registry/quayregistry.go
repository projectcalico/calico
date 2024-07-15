package registry

import (
	"calico_postrelease/pkg/container"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type QuayRegistryResponse struct {
	Tags []struct {
		Name           string `json:"name"`
		Reversion      bool   `json:"reversion"`
		StartTs        int    `json:"start_ts"`
		ManifestDigest string `json:"manifest_digest"`
		IsManifestList bool   `json:"is_manifest_list"`
		Size           int    `json:"size"`
		LastModified   string `json:"last_modified"`
	} `json:"tags"`
	Page          int  `json:"page"`
	HasAdditional bool `json:"has_additional"`
}

type QuayRegistry struct {
	ApiToken string
}

func NewQuayRegistry() QuayRegistry {
	reg := QuayRegistry{
		ApiToken: "asdfasdf",
	}
	return reg
}

func (reg QuayRegistry) CheckImageExists(Image container.Image) error {
	client := &http.Client{}

	api_url := fmt.Sprintf("https://quay.io/api/v1/repository/%s/tag/?specificTag=%s", Image.Name, Image.Tag)
	req, err := http.NewRequest("GET", api_url, nil)
	if err != nil {
		return fmt.Errorf("error! %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error! %v", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("got non-200 status code: %v", resp.StatusCode)
	}

	var body []byte
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var data QuayRegistryResponse
	// var data map[string]interface{}

	err = json.Unmarshal(body, &data)
	if err != nil {
		panic(err)
	}

	if len(data.Tags) > 0 {
		return nil
	} else {
		return fmt.Errorf("no tags found matching %s:%s", Image.Name, Image.Tag)
	}
}
