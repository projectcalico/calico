// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	goerrors "errors"
	"strings"

	"time"

	"encoding/json"

	log "github.com/Sirupsen/logrus"
	etcd "github.com/coreos/etcd/client"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"golang.org/x/net/context"
)

var (
	etcdApplyOpts       = &etcd.SetOptions{PrevExist: etcd.PrevIgnore}
	etcdCreateOpts      = &etcd.SetOptions{PrevExist: etcd.PrevNoExist}
	etcdDeleteEmptyOpts = &etcd.DeleteOptions{Recursive: false, Dir: true}
	etcdGetOpts         = &etcd.GetOptions{Quorum: true}
	etcdListOpts        = &etcd.GetOptions{Quorum: true, Recursive: true, Sort: true}
	clientTimeout       = 30 * time.Second
)

type EtcdConfig struct {
	EtcdScheme     string `json:"etcdScheme" envconfig:"ETCD_SCHEME" default:"http"`
	EtcdAuthority  string `json:"etcdAuthority" envconfig:"ETCD_AUTHORITY" default:"127.0.0.1:2379"`
	EtcdEndpoints  string `json:"etcdEndpoints" envconfig:"ETCD_ENDPOINTS"`
	EtcdUsername   string `json:"etcdUsername" envconfig:"ETCD_USERNAME"`
	EtcdPassword   string `json:"etcdPassword" envconfig:"ETCD_PASSWORD"`
	EtcdKeyFile    string `json:"etcdKeyFile" envconfig:"ETCD_KEY_FILE"`
	EtcdCertFile   string `json:"etcdCertFile" envconfig:"ETCD_CERT_FILE"`
	EtcdCACertFile string `json:"etcdCACertFile" envconfig:"ETCD_CA_CERT_FILE"`
}

type EtcdClient struct {
	etcdClient  etcd.Client
	etcdKeysAPI etcd.KeysAPI
}

func NewEtcdClient(config *EtcdConfig) (*EtcdClient, error) {
	// Determine the location from the authority or the endpoints.  The endpoints
	// takes precedence if both are specified.
	etcdLocation := []string{}
	if config.EtcdAuthority != "" {
		etcdLocation = []string{config.EtcdScheme + "://" + config.EtcdAuthority}
	}
	if config.EtcdEndpoints != "" {
		etcdLocation = strings.Split(config.EtcdEndpoints, ",")
	}

	if len(etcdLocation) == 0 {
		return nil, goerrors.New("no etcd authority or endpoints specified")
	}

	// Create the etcd client
	tls := transport.TLSInfo{
		CAFile:   config.EtcdCACertFile,
		CertFile: config.EtcdCertFile,
		KeyFile:  config.EtcdKeyFile,
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
	if d.Revision != nil {
		options.PrevIndex = d.Revision.(uint64)
	}

	return c.set(d, &options)
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *EtcdClient) Apply(d *model.KVPair) (*model.KVPair, error) {
	return c.set(d, etcdApplyOpts)
}

// Delete an entry in the datastore.  This errors if the entry does not exists.
func (c *EtcdClient) Delete(d *model.KVPair) error {
	key, err := model.KeyToDefaultDeletePath(d.Key)
	if err != nil {
		return err
	}
	etcdDeleteOpts := &etcd.DeleteOptions{Recursive: true}
	if d.Revision != nil {
		etcdDeleteOpts.PrevIndex = d.Revision.(uint64)
	}
	log.Infof("Delete Key: %s", key)
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
		log.Infof("Delete empty Key: %s", parent)
		_, err2 := c.etcdKeysAPI.Delete(context.Background(), parent, etcdDeleteEmptyOpts)
		if err2 != nil {
			log.Infof("Unable to delete parent: %s", err2)
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
	log.Infof("Get Key: %s", key)
	if r, err := c.etcdKeysAPI.Get(context.Background(), key, etcdGetOpts); err != nil {
		return nil, convertEtcdError(err, k)
	} else if v, err := model.ParseValue(k, []byte(r.Node.Value)); err != nil {
		return nil, err
	} else {
		return &model.KVPair{Key: k, Value: v, Revision: r.Node.ModifiedIndex}, nil
	}
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *EtcdClient) List(l model.ListInterface) ([]*model.KVPair, error) {
	// To list entries, we enumerate from the common root based on the supplied
	// IDs, and then filter the results.
	key := model.ListOptionsToDefaultPathRoot(l)
	log.Infof("List Key: %s", key)
	if results, err := c.etcdKeysAPI.Get(context.Background(), key, etcdListOpts); err != nil {
		// If the root key does not exist - that's fine, return no list entries.
		err = convertEtcdError(err, nil)
		switch err.(type) {
		case errors.ErrorResourceDoesNotExist:
			return []*model.KVPair{}, nil
		default:
			return nil, err
		}
	} else {
		list := filterEtcdList(results.Node, l)

		switch t := l.(type) {
		case model.ProfileListOptions:
			return t.ListConvert(list), nil
		}
		return list, nil
	}
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
	bytes, err := json.Marshal(d.Value)
	if err != nil {
		logCxt.WithError(err).Error("Failed to marshal value")
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
	d.Revision = result.Node.ModifiedIndex
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
			kv := &model.KVPair{Key: k, Value: v, Revision: n.ModifiedIndex}
			kvs = append(kvs, kv)
		}
	}
	log.Infof("Returning: %#v", kvs)
	return kvs
}

func convertEtcdError(err error, key model.Key) error {
	if err == nil {
		log.Info("Command completed without error")
		return nil
	}

	switch err.(type) {
	case etcd.Error:
		switch err.(etcd.Error).Code {
		case etcd.ErrorCodeTestFailed:
			log.Info("Test failed error")
			return errors.ErrorResourceUpdateConflict{Identifier: key}
		case etcd.ErrorCodeNodeExist:
			log.Info("Node exists error")
			return errors.ErrorResourceAlreadyExists{Err: err, Identifier: key}
		case etcd.ErrorCodeKeyNotFound:
			log.Info("Key not found error")
			return errors.ErrorResourceDoesNotExist{Err: err, Identifier: key}
		case etcd.ErrorCodeUnauthorized:
			log.Info("Unauthorized error")
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
