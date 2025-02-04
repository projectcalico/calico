package v1

import "github.com/google/uuid"

const (
	VarSubResourceID    = "subResourceName"
	URLVarSubResourceID = sBrc + VarSubResourceID + eBrc

	SubResourcesPath = sep + "subResources"
	SubResourcePath  = SubResourcesPath + sep + URLVarSubResourceID
)

type GetSubResourceParams struct {
	Name         string `urlParam:"subResourceName" validate:"required"`
	ResourceName string `urlParam:"resourceName" validate:"required"`
	AuthToken    string `header:"Authorization" validate:"required"`
}

type GetSubResourceResponse struct {
	ID uuid.UUID
}
