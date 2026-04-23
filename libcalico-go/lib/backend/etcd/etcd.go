// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package etcd

import (
	"context"
	goerrors "errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"go.etcd.io/etcd/client/pkg/v3/srv"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	etcd "go.etcd.io/etcd/client/v2"

	v1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var (
	etcdApplyOpts        = &etcd.SetOptions{PrevExist: etcd.PrevIgnore}
	etcdCreateOpts       = &etcd.SetOptions{PrevExist: etcd.PrevNoExist}
	etcdCreateDirOpts    = &etcd.SetOptions{PrevExist: etcd.PrevNoExist, Dir: true}
	etcdDeleteEmptyOpts  = &etcd.DeleteOptions{Recursive: false, Dir: true}
	etcdGetOpts          = &etcd.GetOptions{Quorum: true}
	etcdListOpts         = &etcd.GetOptions{Quorum: true, Recursive: true, Sort: true}
	etcdListChildrenOpts = &etcd.GetOptions{Quorum: true, Recursive: false, Sort: true}
	clientTimeout        = 30 * time.Second
)

type EtcdClient struct {
	etcdClient  etcd.Client
	etcdKeysAPI etcd.KeysAPI
}

func NewEtcdClient(config *v1.EtcdConfig) (*EtcdClient, error) {
	if (config.EtcdAuthority != "" || config.EtcdEndpoints != "") && config.EtcdDiscoverySrv != "" {
		return nil, goerrors.New("multiple discovery or bootstrap options specified, use either \"etcdEndpoints\" or \"etcdDiscoverySrv\"")
	}

	// Determine the location from the authority or the endpoints.  The endpoints
	// takes precedence if both are specified.
	etcdLocation := []string{}
	if config.EtcdAuthority != "" {
		etcdLocation = []string{config.EtcdScheme + "://" + config.EtcdAuthority}
	}
	if config.EtcdEndpoints != "" {
		etcdLocation = strings.Split(config.EtcdEndpoints, ",")
	}
	if config.EtcdDiscoverySrv != "" {
		srvs, srvErr := srv.GetClient("etcd-client", config.EtcdDiscoverySrv, "")
		if srvErr != nil {
			return nil, fmt.Errorf("failed to discover etcd endpoints through SRV discovery: %v", srvErr)
		}
		etcdLocation = srvs.Endpoints
	}

	if len(etcdLocation) == 0 {
		return nil, goerrors.New("no etcd authority or endpoints specified")
	}

	// Create the etcd client
	tls := transport.TLSInfo{
		TrustedCAFile: config.EtcdCACertFile,
		CertFile:      config.EtcdCertFile,
		KeyFile:       config.EtcdKeyFile,
	}
	transport, err := transport.NewTransport(tls, clientTimeout)
	if err != nil {
		return nil, err
	}

	cfg := etcd.Config{
		Endpoints:               etcdLocation,
		Transport:               transport,
		HeaderTimeoutPerRequest: clientTimeout,
	}

	// Plumb through the username and password if both are configured.
	if config.EtcdUsername != "" && config.EtcdPassword != "" {
		cfg.Username = config.EtcdUsername
		cfg.Password = config.EtcdPassword
	}

	client, err := etcd.New(cfg)
	if err != nil {
		return nil, err
	}
	keys := etcd.NewKeysAPI(client)

	return &EtcdClient{etcdClient: client, etcdKeysAPI: keys}, nil
}

// EnsureInitialized makes sure that the etcd data is initialized for use by
// Calico.
func (c *EtcdClient) EnsureInitialized() error {
	// Make sure the Ready flag is initialized in the datastore
	kv := &model.KVPair{
		Key:   model.ReadyFlagKey{},
		Value: true,
	}
	if _, err := c.Create(kv); err == nil {
		log.Info("Ready flag is now set")
	} else {
		if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
			log.WithError(err).Warn("Failed to set ready flag")
			return err
		}
		log.Info("Ready flag is already set")
	}

	return nil
}

// EnsureCalicoNodeInitialized performs additional initialization required
// by the calico/node components [startup/ipip-allocation/confd].  This is a
// temporary requirement until the calico/node components are updated to not
// require special etcd setup, or until the global and per-node config is
// reworked to allow the node to perform the necessary updates.
func (c *EtcdClient) EnsureCalicoNodeInitialized(node string) error {

	// The confd agent used for BIRD configuration monitors certain
	// directories and doesn't handle the non-existence of these directories
	// very well, so create the required directories.
	dirs := []string{
		"/calico/v1/ipam/v4/pool",
		"/calico/v1/ipam/v6/pool",
		"/calico/bgp/v1/global/custom_filters/v4",
		"/calico/bgp/v1/global/custom_filters/v6",
		"/calico/ipam/v2/host/" + node + "/ipv4/block",
		"/calico/ipam/v2/host/" + node + "/ipv6/block",
	}

	for _, d := range dirs {
		if err := c.ensureDirectory(d); err != nil {
			return err
		}
	}

	return nil
}

func (c *EtcdClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return newSyncer(c.etcdKeysAPI, callbacks)
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *EtcdClient) Create(d *model.KVPair) (*model.KVPair, error) {
	return c.set(d, etcdCreateOpts)
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist.
func (c *EtcdClient) Update(d *model.KVPair) (*model.KVPair, error) {
	// If the request includes a revision, set it as the etcd previous index.
	options := etcd.SetOptions{PrevExist: etcd.PrevExist}
	if len(d.Revision) != 0 {
		var err error
		if options.PrevIndex, err = strconv.ParseUint(d.Revision, 10, 64); err != nil {
			return nil, err
		}
		log.Debugf("Performing CAS against etcd index: %v\n", options.PrevIndex)
	}

	return c.set(d, &options)
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *EtcdClient) Apply(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	return c.set(d, etcdApplyOpts)
}

// Delete an entry in the datastore.  This errors if the entry does not exists.
func (c *EtcdClient) Delete(d *model.KVPair) error {
	key, err := model.KeyToDefaultDeletePath(d.Key)
	if err != nil {
		return err
	}
	etcdDeleteOpts := &etcd.DeleteOptions{Recursive: true}
	if len(d.Revision) != 0 {
		var err error
		if etcdDeleteOpts.PrevIndex, err = strconv.ParseUint(d.Revision, 10, 64); err != nil {
			return err
		}
	}
	log.Debugf("Delete Key: %s", key)
	_, err = c.etcdKeysAPI.Delete(context.Background(), key, etcdDeleteOpts)
	if err != nil {
		return convertEtcdError(err, d.Key)
	}

	// If there are parents to be deleted, delete these as well provided there
	// are no more children.
	parents, err := model.KeyToDefaultDeleteParentPaths(d.Key)
	if err != nil {
		return err
	}
	for _, parent := range parents {
		log.Debugf("Delete empty Key: %s", parent)
		_, err2 := c.etcdKeysAPI.Delete(context.Background(), parent, etcdDeleteEmptyOpts)
		if err2 != nil {
			log.Debugf("Unable to delete parent: %v", err2)
			break
		}
	}

	return convertEtcdError(err, d.Key)
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *EtcdClient) Get(k model.Key) (*model.KVPair, error) {
	key, err := model.KeyToDefaultPath(k)
	if err != nil {
		return nil, err
	}

	log.Debugf("Get Key: %s", key)
	r, err := c.etcdKeysAPI.Get(context.Background(), key, etcdGetOpts)
	if err != nil {
		// Convert the error to our non datastore specific types
		err = convertEtcdError(err, k)

		// Older deployments with etcd may not have the Host metadata, so in the
		// event that the key does not exist, just do a get on the directory to
		// check it exists, and if so return an empty Metadata.
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			if _, ok := k.(model.HostMetadataKey); ok {
				return c.getHostMetadataFromDirectory(k)
			}
		}

		return nil, err
	}

	v, err := model.ParseValue(k, []byte(r.Node.Value))
	if err != nil {
		return nil, err
	}

	return &model.KVPair{Key: k, Value: v, Revision: strconv.FormatUint(r.Node.ModifiedIndex, 10)}, nil
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *EtcdClient) List(l model.ListInterface) ([]*model.KVPair, error) {
	// We need to handle the listing of HostMetadata separately for two reasons:
	// -  older deployments may not have a Metadata, and instead we need to enumerate
	//    based on existence of the directory
	// -  it is not sensible to enumerate all of the endpoints, so better to enumerate
	//    the host directories and then attempt to get the metadata.
	switch lt := l.(type) {
	case model.HostMetadataListOptions:
		return c.listHostMetadata(lt)
	default:
		return c.defaultList(l)
	}
}

// defaultList provides the default list processing.
func (c *EtcdClient) defaultList(l model.ListInterface) ([]*model.KVPair, error) {
	// To list entries, we enumerate from the common root based on the supplied
	// IDs, and then filter the results.
	key := model.ListOptionsToDefaultPathRoot(l)
	log.Debugf("List Key: %s", key)
	results, err := c.etcdKeysAPI.Get(context.Background(), key, etcdListOpts)
	if err != nil {
		// If the root key does not exist - that's fine, return no list entries.
		err = convertEtcdError(err, nil)
		switch err.(type) {
		case errors.ErrorResourceDoesNotExist:
			return []*model.KVPair{}, nil
		default:
			return nil, err
		}
	}

	list := filterEtcdList(results.Node, l)

	switch t := l.(type) {
	case model.ProfileListOptions:
		return t.ListConvert(list), nil
	}

	return list, nil
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *EtcdClient) set(d *model.KVPair, options *etcd.SetOptions) (*model.KVPair, error) {
	logCxt := log.WithFields(log.Fields{
		"key":   d.Key,
		"value": d.Value,
		"ttl":   d.TTL,
		"rev":   d.Revision,
	})
	key, err := model.KeyToDefaultPath(d.Key)
	if err != nil {
		logCxt.WithError(err).Error("Failed to convert key to path")
		return nil, err
	}
	bytes, err := model.SerializeValue(d)
	if err != nil {
		logCxt.WithError(err).Error("Failed to serialize value")
		return nil, err
	}

	value := string(bytes)

	if d.TTL != 0 {
		logCxt.Debug("Key has TTL, copying etcd options")
		// Take a copy of the default options so we can set the TTL for
		// this request only.
		optionsCopy := *options
		optionsCopy.TTL = d.TTL
		options = &optionsCopy
	}
	logCxt.WithField("options", options).Debug("Setting KV in etcd")
	result, err := c.etcdKeysAPI.Set(context.Background(), key, value, options)
	if err != nil {
		// Log at debug because we don't know how serious this is.
		// Caller should log if it's actually a problem.
		logCxt.WithError(err).Debug("Set failed")
		return nil, convertEtcdError(err, d.Key)
	}

	// Datastore object will be identical except for the modified index.
	logCxt.WithField("newRev", result.Node.ModifiedIndex).Debug("Set succeeded")
	d.Revision = strconv.FormatUint(result.Node.ModifiedIndex, 10)
	return d, nil
}

// Process a node returned from a list to filter results based on the List type and to
// compile and return the required results.
func filterEtcdList(n *etcd.Node, l model.ListInterface) []*model.KVPair {
	kvs := []*model.KVPair{}
	if n.Dir {
		for _, node := range n.Nodes {
			kvs = append(kvs, filterEtcdList(node, l)...)
		}
	} else if k := l.KeyFromDefaultPath(n.Key); k != nil {
		if v, err := model.ParseValue(k, []byte(n.Value)); err == nil {
			kv := &model.KVPair{Key: k, Value: v, Revision: strconv.FormatUint(n.ModifiedIndex, 10)}
			kvs = append(kvs, kv)
		}
	}
	log.Debugf("Returning: %#v", kvs)
	return kvs
}

func convertEtcdError(err error, key model.Key) error {
	if err == nil {
		log.Debug("Command completed without error")
		return nil
	}

	switch err.(type) {
	case etcd.Error:
		switch err.(etcd.Error).Code {
		case etcd.ErrorCodeTestFailed:
			log.Debug("Test failed error")
			return errors.ErrorResourceUpdateConflict{Identifier: key}
		case etcd.ErrorCodeNodeExist:
			log.Debug("Node exists error")
			return errors.ErrorResourceAlreadyExists{Err: err, Identifier: key}
		case etcd.ErrorCodeKeyNotFound:
			log.Debug("Key not found error")
			return errors.ErrorResourceDoesNotExist{Err: err, Identifier: key}
		case etcd.ErrorCodeUnauthorized:
			log.Debug("Unauthorized error")
			return errors.ErrorConnectionUnauthorized{Err: err}
		default:
			log.Infof("Generic etcd error error: %v", err)
			return errors.ErrorDatastoreError{Err: err, Identifier: key}
		}
	default:
		log.Infof("Unhandled error: %v", err)
		return errors.ErrorDatastoreError{Err: err, Identifier: key}
	}
}

// getHostMetadataFromDirectory gets hosts that may not be configured with a host
// metadata (older deployments or Openstack deployments).
func (c *EtcdClient) getHostMetadataFromDirectory(k model.Key) (*model.KVPair, error) {
	// The delete path of the host metadata includes the whole of the per-host
	// felix tree, so check the existence of this tree and return and empty
	// Metadata if it exists.
	key, err := model.KeyToDefaultDeletePath(k)
	if err != nil {
		return nil, err
	}
	if _, err := c.etcdKeysAPI.Get(context.Background(), key, etcdGetOpts); err != nil {
		return nil, convertEtcdError(err, k)
	}

	// The node exists, so return an empty Metadata.
	kv := &model.KVPair{
		Key:   k,
		Value: &model.HostMetadata{},
	}
	return kv, nil
}

func (c *EtcdClient) listHostMetadata(l model.HostMetadataListOptions) ([]*model.KVPair, error) {
	// If the hostname is specified then just attempt to get the host,
	// returning an empty string if it does not exist.
	if l.Hostname != "" {
		log.Debug("Listing host metadata with exact key")
		hmk := model.HostMetadataKey{
			Hostname: l.Hostname,
		}

		kv, err := c.Get(hmk)
		if err != nil {
			err = convertEtcdError(err, nil)
			switch err.(type) {
			case errors.ErrorResourceDoesNotExist:
				return []*model.KVPair{}, nil
			default:
				return nil, err
			}
		}

		return []*model.KVPair{kv}, nil
	}

	// No hostname specified, so enumerate the directories directly under
	// the host tree, return no entries if the host directory does not exist.
	log.Debug("Listing all host metadata")
	key := "/calico/v1/host"
	results, err := c.etcdKeysAPI.Get(context.Background(), key, etcdListChildrenOpts)
	if err != nil {
		// If the root key does not exist - that's fine, return no list entries.
		log.WithError(err).Info("Error enumerating host directories")
		err = convertEtcdError(err, nil)
		switch err.(type) {
		case errors.ErrorResourceDoesNotExist:
			return []*model.KVPair{}, nil
		default:
			return nil, err
		}
	}

	// TODO:  Since the host metadata is currently empty, we don't need
	// to perform an additional get here, but in the future when the metadata
	// may contain fields, we would need to perform a get.
	log.Debug("Parse host directories.")
	kvs := []*model.KVPair{}
	for _, n := range results.Node.Nodes {
		k := l.KeyFromDefaultPath(n.Key + "/metadata")
		if k != nil {
			kvs = append(kvs, &model.KVPair{
				Key:   k,
				Value: &model.HostMetadata{},
			})
		}
	}
	return kvs, nil
}

// ensureDirectory makes sure the specified directory exists in etcd.
func (c *EtcdClient) ensureDirectory(dir string) error {
	log.WithField("Dir", dir).Debug("Ensure directory exists")
	_, err := c.etcdKeysAPI.Set(context.Background(), dir, "", etcdCreateDirOpts)
	if err != nil {
		err = convertEtcdError(err, nil)
		if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
			return err
		}
	}
	return nil
}
