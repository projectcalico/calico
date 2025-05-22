package crdv3

import (
	"context"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"k8s.io/apimachinery/pkg/types"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCRDClient(c ctrlclient.Client) resources.K8sResourceClient {
	return &crdClient{c: c}
}

type crdClient struct {
	c ctrlclient.Client
}

// Create creates the object specified in the KVPair, which must not
// already exist. On success, returns a KVPair for the object with
// revision  information filled-in.
func (c *crdClient) Create(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	panic("not implemented") // TODO: Implement
}

// Update modifies the existing object specified in the KVPair.
// On success, returns a KVPair for the object with revision
// information filled-in.  If the input KVPair has revision
// information then the update only succeeds if the revision is still
// current.
func (c *crdClient) Update(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	panic("not implemented") // TODO: Implement
}

// Delete removes the object specified by the Key.  If the call
// contains revision information, the delete only succeeds if the
// revision is still current.
func (c *crdClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	panic("not implemented") // TODO: Implement
}

// DeleteKVP removes the object specified by the KVPair.  If the KVPair
// contains revision information, the delete only succeeds if the
// revision is still current.
func (c *crdClient) DeleteKVP(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	panic("not implemented") // TODO: Implement
}

// Get returns the object identified by the given key as a KVPair with
// revision information.
func (c *crdClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	panic("not implemented") // TODO: Implement
}

// List returns a slice of KVPairs matching the input list options.
// list should be passed one of the model.<Type>ListOptions structs.
// Non-zero fields in the struct are used as filters.
func (c *crdClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	panic("not implemented") // TODO: Implement
}

// Watch returns a WatchInterface used for watching resources matching the
// input list options.
func (c *crdClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	panic("not implemented") // TODO: Implement
}

// EnsureInitialized ensures that the backend is initialized
// any ready to be used.
func (c *crdClient) EnsureInitialized() error {
	return nil
}
