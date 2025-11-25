// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
//
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

// Package syncproto defines the structs used in the Felix/Typha protocol.
//
// # Overview
//
// Felix connects to Typha over a TCP socket, then Felix initiates the (synchronous)
// handshake consisting of a ClientHello then a ServerHello message.
//
// Once the handshake is complete, Typha sends a series of KV pairs to Felix,
// amounting to a complete snapshot of the datastore.  It may send more than one
// KV message, each containing one or more KV pairs.
//
// Once a complete snapshot has been sent, Typha sends a SyncStatus message with
// its current sync status.  This is typically "InSync" but it may be another status,
// such as "Resync" if Typha itself is resyncing with the datastore.
//
// At any point after the  handshake, Typha may send a Ping message, which Felix
// should respond to as quickly as possible with a Pong (if Typha doesn't receive
// a timely response it may terminate the connection).
//
// After the initial snapshot is sent, Typha sends KVs and SyncStatus messages
// as new updates are received from the datastore.
//
//	+-------+                +-------+
//	| Felix |                | Typha |
//	+-------+                +-------+
//	|                        |
//	| connect                |
//	|----------------------->|
//	|                        | -------------------------------\
//	|                        |-| accept, wait for ClientHello |
//	|                        | |------------------------------|
//	|                        |
//	| ClientHello            |
//	|----------------------->|
//	|                        |
//	|            ServerHello |
//	|<-----------------------|
//	|                        |
//	|                        | -------------------------------------------------------\
//	|--------------------------| if compression enabled, restart client's gob decoder |
//	|                        | | send ACK when ready to receive compressed data       |
//	| ACK                    | |------------------------------------------------------|
//	|----------------------->|
//	|                        | -------------------------------------------------------\
//	|                        |-| if compression enabled, restart server's gob encoder |
//	|                        | | with compressed stream                               |
//	|                        | |------------------------------------------------------|
//	|                        |
//	|                        | ------------------------------------\
//	|                        |-| start KV send & pinger goroutines |
//	|                        | |-----------------------------------|
//	|                        |
//	|                KVs * n |
//	|<-----------------------|
//	|                        |
//	|                   Ping |
//	|<-----------------------|
//	|                        |
//	| Pong                   |
//	|----------------------->|
//	|                        |
//	|                KVs * n |
//	|<-----------------------|
//	|                        |
//	|     SyncStatus(InSync) |
//	|<-----------------------|
//	|                        |
//	|                KVs * n |
//	|<-----------------------|
//	|                        |
//
// # Wire format
//
// The protocol uses gob to encode messages.  Each message is wrapped in an Envelope
// struct to simplify decoding.
//
// Key/value pairs are encoded as SerializedUpdate objects.  These contain the KV pair
// along with the Syncer metadata about the update (such as its revision and update type).
// The key and value are encoded to the libcalico-go "default" encoding, as used when
// storing data in, for example, etcd.  I.e. the gob struct contains string and []byte
// fields to hold the key and value, respectively.  Doing this has some advantages:
//
//	(1) It avoids any subtle incompatibility between our datamodel and gob.
//
//	(2) It removes the need to register all our datatypes with the gob en/decoder.
//
//	(3) It re-uses known-good serialization code with known semantics around
//	    data-model upgrade.  I.e. since that serialization is based on the JSON
//	    marshaller, we know how it treats added/removed fields.
//
//	(4) It allows us to do the serialization of each KV pair once and send it to
//	    all listening clients.  (Doing this in gob is not easy because the gob
//	    connection is stateful.)
//
// # Upgrading the datamodel
//
// Some care needs to be taken when upgrading Felix and Typha to ensure that datamodel
// changes are correctly handled.
//
// Since Typha parses resources from the datamodel and then serializes them again,
//
//   - Typha can only pass through resources (and fields) that were present in the
//     version of libcalico-go that it was compiled against.
//
//   - Similarly, Felix can only parse resources and fields that were present in the
//     version of libcalico-go that it was compiled against.
//
//   - It is important that even synthesized resources (for example, those that are
//     generated by the Kubernetes datastore driver) are serializable, even if we never
//     normally write them to a key/value based datastore such as etcd.
//
// In the common case, where a new field is added to the datamodel:
//
//   - If a new Felix connects to an old Typha then Typha will strip the new field
//     at parse-time and pass the object through to Felix.  Hence Felix will behave
//     as if the field wasn't present.  As long as the field was added in a back-compatible
//     way, Felix should default to its old behaviour and the overall outcome will be
//     that new Felix will behave as if it was an old Felix.
//
//   - If an old Felix connects to a new Typha, then Typha will pass through the new
//     field to Felix but Felix will strip it out when it parses the update.
//
// Where a whole new resource is added:
//
//   - If a new Felix connects to an old Typha then Typha will ignore the new resource
//     so it is important that Felix is engineered to allow for missing resources in
//     that case.
//
//   - If an old Felix connects to a new Typha then Typha will send the resource
//     but the old Felix will fail to parse it.  In that case, the Typha client code
//     used by Felix drops the KV pair and logs an error.
//
// In more complicated cases: it's important to think through how the above cases play out.
// For example, removing one synthesized resource type and adding another to take its
// place may no longer work as intended since the new one will get stripped out when
// a mixed Typha/Felix version connection occurs.
//
// If such a change does need to be made, we could treat it as a Typha protocol upgrade
// as described below.
//
// # Upgrading the Typha protocol
//
// In general, even fairly large changes to the protocol can be managed by suitable
// signalling in the handshake.  The most important limitation to be aware of is that
// neither server nor client should send a new message _type_ to the other without
// verifying that the other supports that message type.  In concrete terms, that
// means adding fields to the handshake to advertise support for particular features
// and then for the other side to check that the new field is set before sending the
// new message types.  This works because gob defaults unknown fields to their zero
// value on read, so, if the peer doesn't say "SupportsFeatureX: true" in their
// Hello message, then you'll see "SupportsFeatureX: false" at the other side.
// If you send a message that the peer doesn't understand, decoding will return an
// error.
//
// It's also possible to switch from one protocol to another mid-stream.  We do this
// to enable compression.  The main gotcha is to ensure that no new format data is
// sent until after the other side has acknowledged that it has drained the old
// format data and prepared the new format decoder.  Otherwise the old format decoder
// may eagerly read data in the new format into its buffer and get confused.
package syncproto

import (
	"encoding/gob"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

// Source code for the Sequence diagram above (http://textart.io/sequence).
const _ = `
object Felix Typha
Felix->Typha: connect
note right of Typha: accept, wait for ClientHello
Felix->Typha: ClientHello
Typha->Felix: ServerHello
note right of Typha: start KV send & pinger goroutines
Typha->Felix: KVs * n
Typha->Felix: Ping
Felix->Typha: Pong
Typha->Felix: KVs * n
Typha->Felix: SyncStatus(InSync)
Typha->Felix: KVs * n
`

const DefaultPort = 5473

type Envelope struct {
	Message interface{}
}

// logrus only looks for a String() method on the top-level object, make sure we call through to the wrapped object.
func (e Envelope) String() string {
	return fmt.Sprint("syncproto.Envelope{Message:", e.Message, "}")
}

type SyncerType string

const (
	SyncerTypeFelix              SyncerType = "felix"
	SyncerTypeBGP                SyncerType = "bgp"
	SyncerTypeTunnelIPAllocation SyncerType = "tunnel-ip-allocation"
	SyncerTypeNodeStatus         SyncerType = "node-status"

	// NumSyncerTypes is the number of SyncerType constants above.  For iota to pick up the correct value, all
	// new consts must be added to this block and NumSyncerTypes must be the last entry.
	NumSyncerTypes = iota
)

// AllSyncerTypes contains each of the SyncerType constants. We use an array rather than a slice for a
// compile-time length check.
var AllSyncerTypes = [NumSyncerTypes]SyncerType{
	SyncerTypeFelix,
	SyncerTypeBGP,
	SyncerTypeTunnelIPAllocation,
	SyncerTypeNodeStatus,
}

type CompressionAlgorithm string

const (
	CompressionSnappy CompressionAlgorithm = "snappy"
)

// MsgClientHello is the first message sent by the client after it opens the connection.  It begins the handshake.
// It includes a request to use a particular kind of syncer and tells the server what features are supported.
type MsgClientHello struct {
	Hostname string
	Info     string
	Version  string

	// SyncerType the requested syncer type.  Added in v3.3; if client doesn't provide a value, assumed to be
	// SyncerTypeFelix.
	SyncerType SyncerType

	SupportsDecoderRestart         bool
	SupportedCompressionAlgorithms []CompressionAlgorithm

	// SupportsModernPolicyKeys tells the server whether this client supports modern PolicyKey
	// syntax, i.e., using Kind/Namespace/Name instead of Tier/Name. If the client does not set this field,
	// Typha will reject the connection attempt and wait for the client to be upgraded.
	SupportsModernPolicyKeys bool

	ClientConnID uint64
}

// MsgServerHello is the server's response to MsgClientHello.
type MsgServerHello struct {
	Version string

	// SyncerType the active syncer type; if not specified, implies that the server is an older Typha instance that
	// only supports SyncerTypeFelix.
	SyncerType SyncerType

	// SupportsNodeResourceUpdates provides to the client whether this Typha supports node resource updates.
	SupportsNodeResourceUpdates bool

	ServerConnID uint64
}

// MsgDecoderRestart is sent (currently only from server to client) to tell it to restart its decoder with new
// parameters.
type MsgDecoderRestart struct {
	Message              string
	CompressionAlgorithm CompressionAlgorithm
}

// MsgACK is a general-purpose ACK message, currently used during the initial handshake to acknowledge the
// switch to compressed mode.
type MsgACK struct{}

type MsgSyncStatus struct {
	SyncStatus api.SyncStatus
}

type MsgPing struct {
	Timestamp time.Time
}

type MsgPong struct {
	PingTimestamp time.Time
	PongTimestamp time.Time
}

type MsgKVs struct {
	KVs []SerializedUpdate
}

func (m MsgKVs) String() string {
	var b strings.Builder
	const limit = 10
	b.WriteString("syncproto.MsgKVs{Num:")
	b.WriteString(fmt.Sprint(len(m.KVs)))
	b.WriteString(",KVs:[]{")
	for i, kv := range m.KVs {
		if i > 0 {
			b.WriteString(",")
		}
		if i >= limit {
			b.WriteString("...truncated...")
			break
		}
		b.WriteString(kv.String())
	}
	b.WriteString("}}")
	return b.String()
}

func init() {
	// For forwards/backwards compatibility, we need to use RegisterName here to force consistent names even as
	// code gets refactored/moved/vendored/etc. In particular, this uses the pre-monorepo paths for this package.
	gob.RegisterName("github.com/projectcalico/typha/pkg/syncproto.MsgClientHello", MsgClientHello{})
	gob.RegisterName("github.com/projectcalico/typha/pkg/syncproto.MsgDecoderRestart", MsgDecoderRestart{})
	gob.RegisterName("github.com/projectcalico/typha/pkg/syncproto.MsgACK", MsgACK{})
	gob.RegisterName("github.com/projectcalico/typha/pkg/syncproto.MsgServerHello", MsgServerHello{})
	gob.RegisterName("github.com/projectcalico/typha/pkg/syncproto.MsgSyncStatus", MsgSyncStatus{})
	gob.RegisterName("github.com/projectcalico/typha/pkg/syncproto.MsgPing", MsgPing{})
	gob.RegisterName("github.com/projectcalico/typha/pkg/syncproto.MsgPong", MsgPong{})
	gob.RegisterName("github.com/projectcalico/typha/pkg/syncproto.MsgKVs", MsgKVs{})
}

func SerializeUpdate(u api.Update) (su SerializedUpdate, err error) {
	su.Key, err = model.KeyToDefaultPath(u.Key)
	if err != nil {
		log.WithError(err).WithField("update", u).Error(
			"Bug: failed to serialize key that was generated by Syncer.")
		return
	}

	su.TTL = u.TTL
	su.Revision = u.Revision // This relies on the revision being a basic type.
	su.UpdateType = u.UpdateType

	if u.Value == nil {
		log.Debug("Value is nil, passing through as a deletion.")
		return
	} else if obj, ok := u.Value.(v1.Object); ok {
		// Since Calico v3 objects carry their resource version inside their internal metadata, our
		// later dedupe comparison will always fail.  To counter that, we move the resource version
		// to a field of the SerializedUpdate before we serialize.
		log.Debug("v3 resource, zeroing its internal resource version for dedupe.")
		version := obj.GetResourceVersion()
		su.V3ResourceVersion = version
		defer obj.SetResourceVersion(version) // Restore the input object, mainly for UT.
		obj.SetResourceVersion("")
	}

	value, err := model.SerializeValue(&u.KVPair)
	if err != nil {
		log.WithError(err).WithField("update", u).Error(
			"Bug: failed to serialize value, using nil value (to simulate deletion).")
		err = nil
		return
	}
	su.Value = value

	return
}

type SerializedUpdate struct {
	Key               string
	Value             []byte
	Revision          interface{}
	V3ResourceVersion string
	TTL               time.Duration
	UpdateType        api.UpdateType
}

var ErrBadKey = errors.New("unable to parse key")

var kvRLL = logutils.NewRateLimitedLogger()

func (s SerializedUpdate) ToUpdate() (api.Update, error) {
	// Parse the key.
	parsedKey := model.KeyFromDefaultPath(s.Key)
	if parsedKey == nil {
		kvRLL.WithField("key", s.Key).Warn("Failed to parse key of key/value pair sent from Typha. " +
			"This is normal during upgrade if we're connected to a different version of Typha but it is a bug if Typha " +
			"is the same version as this component.")
		return api.Update{}, ErrBadKey
	}
	var parsedValue interface{}
	if s.Value != nil {
		var err error
		parsedValue, err = model.ParseValue(parsedKey, s.Value)
		if err != nil {
			kvRLL.WithField("rawValue", string(s.Value)).Error(
				"Failed to parse value sent by Typha. This may occur during upgrade if we're connected to a " +
					"different version of Typha but it is a bug if Typha is the same version as this component.")
		} else {
			if obj, ok := parsedValue.(v1.Object); ok {
				log.Debug("v3 resource, populating its internal resource version.")
				obj.SetResourceVersion(fmt.Sprint(s.V3ResourceVersion))
			}
		}
	}
	revStr := ""
	switch r := s.Revision.(type) {
	case string:
		revStr = r
	default:
		revStr = fmt.Sprintf("%v", r)
	}
	return api.Update{
		KVPair: model.KVPair{
			Key:      parsedKey,
			Value:    parsedValue,
			Revision: revStr,
			TTL:      s.TTL,
		},
		UpdateType: s.UpdateType,
	}, nil
}

// WouldBeNoOp returns true if this update would be a no-op given that previous has already been sent.
func (s SerializedUpdate) WouldBeNoOp(previous SerializedUpdate) bool {
	// We don't care if the revision(s) have changed so zero them out.  Note: we're using the fact that this is a
	// value type so these changes won't be propagated to the caller!
	s.Revision = nil
	s.V3ResourceVersion = ""
	previous.Revision = nil
	previous.V3ResourceVersion = ""

	if previous.UpdateType == api.UpdateTypeKVNew {
		// If the old update was a create, convert it to an update before the comparison since it's OK to
		// squash an update to a new key if the value hasn't changed.
		previous.UpdateType = api.UpdateTypeKVUpdated
	}

	return reflect.DeepEqual(s, previous)
}

func (s SerializedUpdate) String() string {
	return fmt.Sprintf("SerializedUpdate<Key:%s, Value:%s, Revision:%v, TTL:%v, UpdateType:%v>",
		s.Key, string(s.Value), s.Revision, s.TTL, s.UpdateType)
}
