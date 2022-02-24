// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package bpf

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type IteratorAction string

const (
	IterNone   IteratorAction = ""
	IterDelete IteratorAction = "delete"
)

type IterCallback func(k, v []byte) IteratorAction

type Map interface {
	GetName() string
	// EnsureExists opens the map, creating and pinning it if needed.
	EnsureExists() error
	// Open opens the map, returns error if it does not exist.
	Open() error
	// MapFD gets the file descriptor of the map, only valid after calling EnsureExists().
	MapFD() MapFD
	// Path returns the path that the map is (to be) pinned to.
	Path() string

	Iter(IterCallback) error
	Update(k, v []byte) error
	Get(k []byte) ([]byte, error)
	Delete(k []byte) error
}

type MapParameters struct {
	Filename   string
	Type       string
	KeySize    int
	ValueSize  int
	MaxEntries int
	Name       string
	Flags      int
	Version    int
}

func versionedStr(ver int, str string) string {
	if ver <= 1 {
		return str
	}

	return fmt.Sprintf("%s%d", str, ver)
}

func (mp *MapParameters) VersionedName() string {
	return versionedStr(mp.Version, mp.Name)
}

func (mp *MapParameters) versionedFilename() string {
	return versionedStr(mp.Version, mp.Filename)
}

type MapContext struct {
	RepinningEnabled bool
	IpsetsMap        Map
	StateMap         Map
	ArpMap           Map
	FailsafesMap     Map
	FrontendMap      Map
	BackendMap       Map
	AffinityMap      Map
	RouteMap         Map
	CtMap            Map
	SrMsgMap         Map
	CtNatsMap        Map
	MapSizes         map[string]uint32
}

func (c *MapContext) NewPinnedMap(params MapParameters) Map {
	if len(params.VersionedName()) >= unix.BPF_OBJ_NAME_LEN {
		logrus.WithField("name", params.Name).Panic("Bug: BPF map name too long")
	}
	if val, ok := c.MapSizes[params.VersionedName()]; ok {
		params.MaxEntries = int(val)
	}

	m := &PinnedMap{
		context:       c,
		MapParameters: params,
		perCPU:        strings.Contains(params.Type, "percpu"),
	}
	return m
}

type PinnedMap struct {
	context *MapContext
	MapParameters

	fdLoaded bool
	fd       MapFD
	perCPU   bool
}

func (b *PinnedMap) GetName() string {
	return b.VersionedName()
}

func (b *PinnedMap) MapFD() MapFD {
	if !b.fdLoaded {
		logrus.WithField("map", *b).Panic("MapFD() called without first calling EnsureExists()")
	}
	return b.fd
}

func (b *PinnedMap) Path() string {
	return b.versionedFilename()
}

func (b *PinnedMap) Close() error {
	err := b.fd.Close()
	b.fdLoaded = false
	b.fd = 0
	return err
}

func (b *PinnedMap) RepinningEnabled() bool {
	if b.context == nil {
		return false
	}
	return b.context.RepinningEnabled
}

func ShowMapCmd(m Map) ([]string, error) {
	if pm, ok := m.(*PinnedMap); ok {
		return []string{
			"bpftool",
			"--json",
			"--pretty",
			"map",
			"show",
			"pinned",
			pm.versionedFilename(),
		}, nil
	}

	return nil, errors.Errorf("unrecognized map type %T", m)
}

// DumpMapCmd returns the command that can be used to dump a map or an error
func DumpMapCmd(m Map) ([]string, error) {
	if pm, ok := m.(*PinnedMap); ok {
		return []string{
			"bpftool",
			"--json",
			"--pretty",
			"map",
			"dump",
			"pinned",
			pm.versionedFilename(),
		}, nil
	}

	return nil, errors.Errorf("unrecognized map type %T", m)
}

func MapDeleteKeyCmd(m Map, key []byte) ([]string, error) {
	if pm, ok := m.(*PinnedMap); ok {
		keyData := make([]string, len(key))
		for i, b := range key {
			keyData[i] = fmt.Sprintf("%d", b)
		}
		cmd := []string{
			"bpftool",
			"--json",
			"--pretty",
			"map",
			"delete",
			"pinned",
			pm.versionedFilename(),
			"key",
		}

		cmd = append(cmd, keyData...)

		return cmd, nil
	}

	return nil, errors.Errorf("unrecognized map type %T", m)
}

// IterMapCmdOutput iterates over the outout of a command obtained by DumpMapCmd
func IterMapCmdOutput(output []byte, f IterCallback) error {
	var mp []mapEntry
	err := json.Unmarshal(output, &mp)
	if err != nil {
		return errors.Errorf("cannot parse json output: %v\n%s", err, output)
	}

	for _, me := range mp {
		k, err := hexStringsToBytes(me.Key)
		if err != nil {
			return errors.Errorf("failed parsing entry %s key: %e", me, err)
		}
		v, err := hexStringsToBytes(me.Value)
		if err != nil {
			return errors.Errorf("failed parsing entry %s val: %e", me, err)
		}
		f(k, v)
	}

	return nil
}

// Iter iterates over the map, passing each key/value pair to the provided callback function.  Warning:
// The key and value are owned by the iterator and will be clobbered by the next iteration so they must not be
// retained or modified.
func (b *PinnedMap) Iter(f IterCallback) error {
	it, err := NewMapIterator(b.MapFD(), b.KeySize, b.ValueSize, b.MaxEntries)
	if err != nil {
		return fmt.Errorf("failed to create BPF map iterator: %w", err)
	}
	defer func() {
		err := it.Close()
		if err != nil {
			logrus.WithError(err).Panic("Unexpected error from map iterator Close().")
		}
	}()

	keyToDelete := make([]byte, b.KeySize)
	var action IteratorAction
	for {
		k, v, err := it.Next()

		if action == IterDelete {
			// The previous iteration asked us to delete its key; do that now before we check for the end of
			// the iteration.
			err := DeleteMapEntry(b.MapFD(), keyToDelete, b.ValueSize)
			if err != nil && !IsNotExists(err) {
				return fmt.Errorf("failed to delete map entry: %w", err)
			}
		}

		if err != nil {
			if err == ErrIterationFinished {
				return nil
			}
			return errors.Errorf("iterating the map failed: %s", err)
		}

		action = f(k, v)

		if action == IterDelete {
			// k will become invalid once we call Next again so take a copy.
			copy(keyToDelete, k)
		}
	}
}

func (b *PinnedMap) Update(k, v []byte) error {
	if b.perCPU {
		// Per-CPU maps need a buffer of value-size * num-CPUs.
		logrus.Panic("Per-CPU operations not implemented")
	}
	return UpdateMapEntry(b.fd, k, v)
}

func (b *PinnedMap) Get(k []byte) ([]byte, error) {
	if b.perCPU {
		// Per-CPU maps need a buffer of value-size * num-CPUs.
		logrus.Panic("Per-CPU operations not implemented")
	}
	return GetMapEntry(b.fd, k, b.ValueSize)
}

func (b *PinnedMap) Delete(k []byte) error {
	if b.perCPU {
		logrus.Panic("Per-CPU operations not implemented")
	}
	return DeleteMapEntry(b.fd, k, b.ValueSize)
}

func (b *PinnedMap) Open() error {
	if b.fdLoaded {
		return nil
	}

	_, err := MaybeMountBPFfs()
	if err != nil {
		logrus.WithError(err).Error("Failed to mount bpffs")
		return err
	}
	// FIXME hard-coded dir
	err = os.MkdirAll("/sys/fs/bpf/tc/globals", 0700)
	if err != nil {
		logrus.WithError(err).Error("Failed create dir")
		return err
	}

	_, err = os.Stat(b.versionedFilename())
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		logrus.Debug("Map file didn't exist")
		if b.context.RepinningEnabled {
			logrus.WithField("name", b.Name).Info("Looking for map by name (to repin it)")
			err = RepinMap(b.VersionedName(), b.versionedFilename())
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}

	if err == nil {
		logrus.Debug("Map file already exists, trying to open it")
		b.fd, err = GetMapFDByPin(b.versionedFilename())
		if err == nil {
			b.fdLoaded = true
			logrus.WithField("fd", b.fd).WithField("name", b.versionedFilename()).
				Info("Loaded map file descriptor.")
			return nil
		}
		return err
	}

	return err
}

// nolint
func (b *PinnedMap) migratePinnedMap(from, to string) error {
	err := RepinMap(b.VersionedName(), to)
	if err != nil {
		return fmt.Errorf("error repinning %s to %s: %w", from, to, err)
	}
	err = os.Remove(from)
	if err != nil {
		return fmt.Errorf("error removing the pin %s", from)
	}
	return nil
}

func (b *PinnedMap) oldMapExists() bool {
	_, err := os.Stat(b.Path() + "_old")
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func (b *PinnedMap) EnsureExists() error {
	oldMapPath := b.Path() + "_old"
	if b.fdLoaded {
		return nil
	}

	// In case felix restarts in the middle of migration, we might end up with
	// old map. Repin the old map and let the map creation continue.
	if b.oldMapExists() {
		if _, err := os.Stat(b.Path()); err == nil {
			os.Remove(b.Path())
		}
		err := b.migratePinnedMap(oldMapPath, b.Path())
		if err != nil {
			return fmt.Errorf("error repinning old map %s to %s, err=%w", oldMapPath, b.Path(), err)
		}
	}

	if err := b.Open(); err == nil {
		// Get the existing map info
		mapInfo, err := GetMapInfo(b.fd)
		if err != nil {
			return fmt.Errorf("error getting map info of the pinned map %w", err)
		}

		if b.MaxEntries == mapInfo.MaxEntries {
			return nil
		}
		// close the map fd to remove the map from the kernel
		b.MapFD().Close()
		err = b.migratePinnedMap(b.Path(), oldMapPath)
		if err != nil {
			return fmt.Errorf("error migrating the old map %w", err)
		}
	}

	logrus.Debug("Map didn't exist, creating it")
	cmd := exec.Command("bpftool", "map", "create", b.versionedFilename(),
		"type", b.Type,
		"key", fmt.Sprint(b.KeySize),
		"value", fmt.Sprint(b.ValueSize),
		"entries", fmt.Sprint(b.MaxEntries),
		"name", b.VersionedName(),
		"flags", fmt.Sprint(b.Flags),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logrus.WithField("out", string(out)).Error("Failed to run bpftool")
		return err
	}
	b.fd, err = GetMapFDByPin(b.versionedFilename())
	if err == nil {
		b.fdLoaded = true
		// Delete the old pin if migration had happened and migration was successful.
		if _, err := os.Stat(oldMapPath); err == nil {
			os.Remove(b.Path() + "_old")
		}
		logrus.WithField("fd", b.fd).WithField("name", b.versionedFilename()).
			Info("Loaded map file descriptor.")
	}
	return err
}

type bpftoolMapMeta struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func RepinMap(name string, filename string) error {
	cmd := exec.Command("bpftool", "map", "list", "-j")
	out, err := cmd.Output()
	if err != nil {
		return errors.Wrap(err, "bpftool map list failed")
	}
	logrus.WithField("maps", string(out)).Debug("Got map metadata.")

	var maps []bpftoolMapMeta
	err = json.Unmarshal(out, &maps)
	if err != nil {
		return errors.Wrap(err, "bpftool returned bad JSON")
	}

	for _, m := range maps {
		if m.Name == name {
			// Found the map, try to repin it.
			cmd := exec.Command("bpftool", "map", "pin", "id", fmt.Sprint(m.ID), filename)
			return errors.Wrap(cmd.Run(), "bpftool failed to repin map")
		}
	}

	return os.ErrNotExist
}
