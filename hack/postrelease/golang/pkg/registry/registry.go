package registry

type Registry interface {
	CheckImageExists() error
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
