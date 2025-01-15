package v1

import "github.com/google/uuid"

const (
	VarResourceID    = "resourceID"
	URLVarResourceID = sBrc + VarResourceID + eBrc

	ResourcesPath = sep + "resources"
	ResourcePath  = ResourcesPath + sep + URLVarResourceID
)

type GetResourceParams struct {
	ID        uuid.UUID `urlParam:"resourceID" validate:"required"`
	AuthToken string    `header:"Authorization" validate:"required"`
}

type ListResourceParams struct {
	Name string `urlParam:"resourceName" validate:"required"`
}

type GetResourceResponse struct {
	ID uuid.UUID
}
