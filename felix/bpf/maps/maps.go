// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.
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

package maps

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/utils"
)

func IsNotExists(err error) bool {
	return err == unix.ENOENT
}

var (
	cachedNumPossibleCPUs     int
	cachedNumPossibleCPUsOnce sync.Once
)

func NumPossibleCPUs() int {
	cachedNumPossibleCPUsOnce.Do(func() {
		var err error
		cachedNumPossibleCPUs, err = libbpf.NumPossibleCPUs()
		if err != nil {
			log.WithError(err).Panic("Failed to read the number of possible CPUs from libbpf.")
		}
	})
	return cachedNumPossibleCPUs
}

type FD uint32

func (f FD) Close() error {
	log.WithField("fd", int(f)).Debug("Closing map FD")
	return unix.Close(int(f))
}

type IteratorAction string

const (
	IterNone   IteratorAction = ""
	IterDelete IteratorAction = "delete"
)

type AsBytes interface {
	AsBytes() []byte
}

type Key interface {
	comparable
	AsBytes
}

type Value interface {
	comparable
	AsBytes
}

var (
	repinningEnabled     bool
	repinningEnabledLock sync.RWMutex
)

func EnableRepin() {
	repinningEnabledLock.Lock()
	defer repinningEnabledLock.Unlock()

	repinningEnabled = true
}

func DisableRepin() {
	repinningEnabledLock.Lock()
	defer repinningEnabledLock.Unlock()

	repinningEnabled = false
}

func repinningIsEnabled() bool {
	repinningEnabledLock.RLock()
	defer repinningEnabledLock.RUnlock()

	return repinningEnabled
}

type IterCallback func(k, v []byte) IteratorAction

type Map interface {
	GetName() string
	// EnsureExists opens the map, creating and pinning it if needed.
	EnsureExists() error
	// Open opens the map, returns error if it does not exist.
	Open() error
	// Close closes the map, returns error for any error.
	Close() error
	// MapFD gets the file descriptor of the map, only valid after calling EnsureExists().
	MapFD() FD
	// Path returns the path that the map is (to be) pinned to.
	Path() string

	// CopyDeltaFromOldMap() copies data from old map to new map
	CopyDeltaFromOldMap() error

	Iter(IterCallback) error
	Update(k, v []byte) error
	Get(k []byte) ([]byte, error)
	Delete(k []byte) error
}

type MapWithExistsCheck interface {
	Map
	ErrIsNotExists(error) bool
}

type MapWithUpdateWithFlags interface {
	Map
	UpdateWithFlags(k, v []byte, flags int) error
}

type MapWithDeleteIfExists interface {
	Map
	DeleteIfExists(k []byte) error
}

type MapParameters struct {
	PinDir       string
	Type         string
	KeySize      int
	ValueSize    int
	MaxEntries   int
	Name         string
	Flags        int
	Version      int
	UpdatedByBPF bool
}

func versionedStr(ver int, str string) string {
	if ver <= 1 {
		return str
	}

	return fmt.Sprintf("%s%d", str, ver)
}

func (mp *MapParameters) pinDir() string {
	pindir := bpfdefs.GlobalPinDir
	if mp.PinDir != "" {
		pindir = mp.PinDir
	}

	return pindir
}

func (mp *MapParameters) VersionedName() string {
	return versionedStr(mp.Version, mp.Name)
}

func (mp *MapParameters) VersionedFilename() string {
	return path.Join(mp.pinDir(), mp.VersionedName())
}

var (
	defaultMapsSizes = make(map[string]int)
	mapSizes         = make(map[string]int)
	mapSizesLock     sync.RWMutex
)

func SetSize(name string, size int) {
	mapSizesLock.Lock()
	defer mapSizesLock.Unlock()

	if _, ok := defaultMapsSizes[name]; !ok {
		defaultMapsSizes[name] = size
	}
	mapSizes[name] = size
}

func Size(name string) int {
	mapSizesLock.RLock()
	defer mapSizesLock.RUnlock()

	if sz, ok := mapSizes[name]; ok {
		return sz
	}

	return defaultMapsSizes[name]
}

func ResetSizes() {
	mapSizesLock.Lock()
	defer mapSizesLock.Unlock()

	mapSizes = make(map[string]int)
}

func NewPinnedMap(params MapParameters) *PinnedMap {
	if len(params.VersionedName()) >= unix.BPF_OBJ_NAME_LEN {
		log.WithField("name", params.Name).Panic("Bug: BPF map name too long")
	}
	if val := Size(params.VersionedName()); val != 0 {
		params.MaxEntries = val
	}

	m := &PinnedMap{
		MapParameters: params,
		perCPU:        strings.Contains(params.Type, "percpu"),
	}
	return m
}

type PinnedMap struct {
	MapParameters

	fdLoaded bool
	fd       FD
	oldfd    FD
	perCPU   bool
	oldSize  int
	// Callbacks to handle upgrade
	UpgradeFn      func(*PinnedMap, *PinnedMap) error
	GetMapParams   func(int) MapParameters
	KVasUpgradable func(int, []byte, []byte) (Upgradable, Upgradable)
}

func (b *PinnedMap) GetName() string {
	return b.VersionedName()
}

func (b *PinnedMap) MapFD() FD {
	if !b.fdLoaded {
		log.WithField("map", *b).Panic("MapFD() called without first calling EnsureExists()")
	}
	return b.fd
}

func (b *PinnedMap) Path() string {
	return b.VersionedFilename()
}

func (b *PinnedMap) Close() error {
	err := b.fd.Close()
	if b.oldfd > 0 {
		b.oldfd.Close()
	}
	b.fdLoaded = false
	b.oldfd = 0
	b.fd = 0
	return err
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
			pm.VersionedFilename(),
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
			pm.VersionedFilename(),
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
			pm.VersionedFilename(),
			"key",
		}

		cmd = append(cmd, keyData...)

		return cmd, nil
	}

	return nil, errors.Errorf("unrecognized map type %T", m)
}

// Iter iterates over the map, passing each key/value pair to the provided callback function.  Warning:
// The key and value are owned by the iterator and will be clobbered by the next iteration so they must not be
// retained or modified.
func (b *PinnedMap) Iter(f IterCallback) error {
	valueSize := b.ValueSize
	if b.perCPU {
		valueSize = b.ValueSize * NumPossibleCPUs()
	}
	it, err := NewIterator(b.MapFD(), b.KeySize, valueSize, b.MaxEntries)
	if err != nil {
		return fmt.Errorf("failed to create BPF map iterator: %w", err)
	}
	defer func() {
		err := it.Close()
		if err != nil {
			log.WithError(err).Panic("Unexpected error from map iterator Close().")
		}
	}()

	keyToDelete := make([]byte, b.KeySize)
	var action IteratorAction
	for {
		k, v, err := it.Next()

		if action == IterDelete {
			// The previous iteration asked us to delete its key; do that now before we check for the end of
			// the iteration.
			err := DeleteMapEntry(b.MapFD(), keyToDelete)
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

func (*PinnedMap) ErrIsNotExists(err error) bool {
	return IsNotExists(err)
}

func (b *PinnedMap) Update(k, v []byte) error {
	if b.perCPU {
		// Per-CPU maps need a buffer of value-size * num-CPUs.
		if len(v) < b.ValueSize*NumPossibleCPUs() {
			return fmt.Errorf("Not enough data for per-cpu map entry")
		}
	}
	return UpdateMapEntry(b.fd, k, v)
}

func (b *PinnedMap) UpdateWithFlags(k, v []byte, flags int) error {
	if b.perCPU {
		// Per-CPU maps need a buffer of value-size * num-CPUs.
		if len(v) < b.ValueSize*NumPossibleCPUs() {
			return fmt.Errorf("Not enough data for per-cpu map entry")
		}
	}
	return UpdateMapEntryWithFlags(b.fd, k, v, flags)
}

func (b *PinnedMap) Get(k []byte) ([]byte, error) {
	valueSize := b.ValueSize
	if b.perCPU {
		valueSize = b.ValueSize * NumPossibleCPUs()
		log.Debugf("Set value size to %v for getting an entry from Per-CPU map", valueSize)
	}
	return GetMapEntry(b.fd, k, valueSize)
}

func (b *PinnedMap) Delete(k []byte) error {
	return DeleteMapEntry(b.fd, k)
}

func (b *PinnedMap) DeleteIfExists(k []byte) error {
	return DeleteMapEntryIfExists(b.fd, k)
}

func (b *PinnedMap) updateDeltaEntries() error {
	log.WithField("name", b.Name).Debug("updateDeltaEntries")

	if b.oldfd == b.fd {
		return fmt.Errorf("old and new maps are the same")
	}

	log.WithField("name", b.Name).Debugf("updateDeltaEntries from fd %d -> %d", b.oldfd, b.fd)

	numEntriesCopied := 0
	mapMem := make(map[string]struct{})
	it, err := NewIterator(b.oldfd, b.KeySize, b.ValueSize, b.oldSize)
	if err != nil {
		return fmt.Errorf("failed to create BPF map iterator: %w", err)
	}
	log.WithField("name", b.Name).Debugf("updateDeltaEntries iterator over fd %d", b.oldfd)
	defer func() {
		err := it.Close()
		if err != nil {
			log.WithError(err).Panic("Unexpected error from map iterator Close().")
		}
	}()
	for {
		k, v, err := it.Next()

		if err != nil {
			if err == ErrIterationFinished {
				break
			}
			return errors.Errorf("iterating the old map failed: %s", err)
		}
		if numEntriesCopied == b.MaxEntries {
			return fmt.Errorf("new map cannot hold all the data from the old map %s.", b.GetName())
		}

		if _, ok := mapMem[string(k)]; ok {
			continue
		}
		newValue, err := b.Get(k)
		if err == nil && reflect.DeepEqual(newValue, v) {
			numEntriesCopied++
			continue
		}
		err = b.Update(k, v)
		if err != nil {
			return fmt.Errorf("error copying data from the old map")
		}
		log.Debugf("copied data from old map to new map key=%v, value=%v", k, v)
		mapMem[string(k)] = struct{}{}
		numEntriesCopied++
	}

	log.WithField("name", b.Name).Debugf("updateDeltaEntries copied %d", numEntriesCopied)

	return nil
}

func (b *PinnedMap) copyFromOldMap() error {
	numEntriesCopied := 0
	mapMem := make(map[string]struct{})
	it, err := NewIterator(b.oldfd, b.KeySize, b.ValueSize, b.oldSize)
	if err != nil {
		return fmt.Errorf("failed to create BPF map iterator: %w", err)
	}
	defer func() {
		err := it.Close()
		if err != nil {
			log.WithError(err).Panic("Unexpected error from map iterator Close().")
		}
	}()

	for {
		k, v, err := it.Next()

		if err != nil {
			if err == ErrIterationFinished {
				return nil
			}
			return errors.Errorf("iterating the old map failed: %s", err)
		}

		if numEntriesCopied == b.MaxEntries {
			return fmt.Errorf("new map cannot hold all the data from the old map %s", b.GetName())
		}
		if _, ok := mapMem[string(k)]; ok {
			continue
		}

		err = b.Update(k, v)
		if err != nil {
			return fmt.Errorf("error copying data from the old map")
		}
		log.WithField("name", b.Name).Debugf("copied data from old map to new map key=%v, value=%v", k, v)
		mapMem[string(k)] = struct{}{}
		numEntriesCopied++
	}
}

func (b *PinnedMap) Open() error {
	if b.fdLoaded {
		log.WithField("name", b.Name).Debug("Open - fd loaded")
		return nil
	}

	_, err := utils.MaybeMountBPFfs()
	if err != nil {
		log.WithError(err).Error("Failed to mount bpffs")
		return err
	}
	pindir := b.pinDir()
	err = os.MkdirAll(pindir, 0700)
	if err != nil {
		log.WithError(err).Error("Failed create dir")
		return err
	}

	_, err = os.Stat(b.VersionedFilename())
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		log.WithField("name", b.Name).Debug("Map file didn't exist")
		if repinningIsEnabled() {
			log.WithField("name", b.Name).Info("Looking for map by name (to repin it)")
			err = RepinMap(b.VersionedName(), b.VersionedFilename())
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}

	if err == nil {
		log.WithField("name", b.Name).Debug("Map file already exists, trying to open it")
		b.fd, err = GetMapFDByPin(b.VersionedFilename())
		if err == nil {
			b.fdLoaded = true
			log.WithField("fd", b.fd).WithField("name", b.Name).Info("Loaded map file descriptor.")
			return nil
		}
		return err
	}

	return err
}

func (b *PinnedMap) repinAt(fd int, from, to string) error {
	err := libbpf.ObjPin(fd, to)
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
	copyData := false
	if b.fdLoaded {
		return nil
	}

	// In case felix restarts in the middle of migration, we might end up with
	// old map. Repin the old map and let the map creation continue.
	if b.oldMapExists() {
		log.WithField("name", b.Name).Debug("Old map exists")
		if _, err := os.Stat(b.Path()); err == nil {
			os.Remove(b.Path())
		}
		fd, err := libbpf.ObjGet(oldMapPath)
		if err != nil {
			return fmt.Errorf("cannot get old map at %s: %w", oldMapPath, err)
		}
		err = b.repinAt(fd, oldMapPath, b.Path())
		syscall.Close(fd)
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
		log.WithField("name", b.Name).Debugf("Size changed %d -> %d", mapInfo.MaxEntries, b.MaxEntries)

		// store the old fd
		b.oldfd = b.MapFD()
		b.oldSize = mapInfo.MaxEntries

		err = b.repinAt(int(b.MapFD()), b.Path(), oldMapPath)
		if err != nil {
			return fmt.Errorf("error migrating the old map %w", err)
		}
		copyData = true
		// Do not close the oldfd if the map is updated by the BPF programs.
		if !b.UpdatedByBPF {
			defer func() {
				b.oldfd.Close()
				b.oldfd = 0
			}()
		}
	}

	log.WithField("name", b.Name).Debug("Map didn't exist, creating it")
	cmd := exec.Command("bpftool", "map", "create", b.VersionedFilename(),
		"type", b.Type,
		"key", fmt.Sprint(b.KeySize),
		"value", fmt.Sprint(b.ValueSize),
		"entries", fmt.Sprint(b.MaxEntries),
		"name", b.VersionedName(),
		"flags", fmt.Sprint(b.Flags),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithField("out", string(out)).Error("Failed to run bpftool")
		return err
	}
	b.fd, err = GetMapFDByPin(b.VersionedFilename())
	if err == nil {
		b.fdLoaded = true
		if copyData {
			// Copy data from old map to the new map. Old map and new map are of the
			// same version but of different size.
			err := b.copyFromOldMap()
			if err != nil {
				b.fd.Close()
				b.fd = 0
				b.fdLoaded = false
				log.WithError(err).Error("error copying data from old map")
				return err
			}
			// Delete the old pin if the map is not updated by BPF programs.
			// Data from old map to new map will be copied once all the bpf
			// programs are installed with the new map.
			if !b.UpdatedByBPF {
				os.Remove(b.Path() + "_old")
			}

		}
		// Handle map upgrade.
		err = b.upgrade()
		if err != nil {
			b.fd.Close()
			b.fd = 0
			b.fdLoaded = false
			return err
		}
		log.WithField("fd", b.fd).WithField("name", b.VersionedFilename()).
			Info("Loaded map file descriptor.")
	}
	return err
}

type bpftoolMapMeta struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func GetMapIdFromPin(pinPath string) (int, error) {
	cmd := exec.Command("bpftool", "map", "list", "pinned", pinPath, "-j")
	out, err := cmd.Output()
	if err != nil {
		return -1, errors.Wrap(err, "bpftool map list failed")
	}

	var mapData bpftoolMapMeta
	err = json.Unmarshal(out, &mapData)
	if err != nil {
		return -1, errors.Wrap(err, "bpftool returned bad JSON")
	}
	return mapData.ID, nil
}

// RepinMap finds a map by a given name and pins it to a path. Note that if
// there are multiple maps of the same name in the system, it will use the first
// one it finds.
func RepinMap(name string, filename string) error {
	cmd := exec.Command("bpftool", "map", "list", "-j")
	out, err := cmd.Output()
	if err != nil {
		return errors.Wrap(err, "bpftool map list failed")
	}

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

func (b *PinnedMap) CopyDeltaFromOldMap() error {
	// check if there is any old version of the map.
	// If so upgrade delta entries from the old map
	// to the new map.

	log.WithField("name", b.Name).Debug("CopyDeltaFromOldMap")

	err := b.upgrade()
	if err != nil {
		return fmt.Errorf("error upgrading data from old map %s, err=%w", b.GetName(), err)
	}
	if b.oldfd == 0 {
		log.WithField("name", b.Name).Debug("CopyDeltaFromOldMap - no old map, done.")
		return nil
	}

	defer func() {
		b.oldfd.Close()
		b.oldfd = 0
		os.Remove(b.Path() + "_old")
	}()

	err = b.updateDeltaEntries()
	if err != nil {
		return fmt.Errorf("error copying data from old map %s, err=%w", b.GetName(), err)
	}
	return nil
}

func (b *PinnedMap) getOldMapVersion() (int, error) {
	oldVersion := 0
	name := b.Name
	files, err := os.ReadDir(b.pinDir())
	if err != nil {
		return 0, fmt.Errorf("error reading pin path %w", err)
	}
	for _, f := range files {
		fname := f.Name()
		if len(fname) >= len(name) && fname[0:len(name)] == name {
			oldIdx := strings.Index(fname, "_old")
			if oldIdx == -1 {
				oldIdx = len(fname)
			}
			oldVersion, err = strconv.Atoi(fname[len(name):oldIdx])
			if err != nil {
				// We may have names that have the same prefix. Don't error,
				// just continue. We eventually run out of maps.
				continue
			}
			if oldVersion < b.Version {
				return oldVersion, nil
			}
			if oldVersion > b.Version {
				return 0, fmt.Errorf("downgrade not supported %d %d", oldVersion, b.Version)
			}
			oldVersion = 0
		}
	}
	return oldVersion, nil
}

// This function upgrades entries from one version of the map to the other.
// Say we move from mapv2 to mapv3. Data from v2 is upgraded to v3.
// If there is a resized version of v2, which is v2_old, data is upgraded from
// v2_old as well to v3.
func (b *PinnedMap) upgrade() error {
	log.WithField("name", b.Name).Debug("upgrade")
	if b.UpgradeFn == nil {
		return nil
	}
	if b.GetMapParams == nil || b.KVasUpgradable == nil {
		return fmt.Errorf("upgrade callbacks not registered %s", b.Name)
	}
	oldVersion, err := b.getOldMapVersion()
	log.WithError(err).Debugf("Upgrading from %d", oldVersion)
	if err != nil {
		return err
	}
	// fresh install
	if oldVersion == 0 {
		return nil
	}

	// Get a pinnedMap handle for the old map
	oldMapParams := b.GetMapParams(oldVersion)
	oldMapParams.MaxEntries = b.MaxEntries
	oldBpfMap := NewPinnedMap(oldMapParams)
	defer func() {
		oldBpfMap.Close()
		oldBpfMap.fd = 0
	}()
	err = oldBpfMap.EnsureExists()
	if err != nil {
		return err
	}
	return b.UpgradeFn(oldBpfMap, b)
}

type Upgradable interface {
	Upgrade() Upgradable
	AsBytes() []byte
}

type TypedMap[K Key, V Value] struct {
	untypedMap   MapWithExistsCheck
	kConstructor func([]byte) K
	vConstructor func([]byte) V
}

func (m *TypedMap[K, V]) ErrIsNotExists(err error) bool {
	return m.untypedMap.ErrIsNotExists(err)
}

func (m *TypedMap[K, V]) Update(k K, v V) error {
	return m.untypedMap.Update(k.AsBytes(), v.AsBytes())
}

func (m *TypedMap[K, V]) Get(k K) (V, error) {
	var res V

	vb, err := m.untypedMap.Get(k.AsBytes())
	if err != nil {
		goto exit
	}

	res = m.vConstructor(vb)

exit:
	return res, err
}

func (m *TypedMap[K, V]) Delete(k K) error {
	return m.untypedMap.Delete(k.AsBytes())
}

func (m *TypedMap[K, V]) Load() (map[K]V, error) {

	memMap := make(map[K]V)

	err := m.untypedMap.Iter(func(kb, vb []byte) IteratorAction {
		memMap[m.kConstructor(kb)] = m.vConstructor(vb)
		return IterNone
	})

	return memMap, err
}

func NewTypedMap[K Key, V Value](m MapWithExistsCheck, kConstructor func([]byte) K, vConstructor func([]byte) V) *TypedMap[K, V] {
	return &TypedMap[K, V]{
		untypedMap:   m,
		kConstructor: kConstructor,
		vConstructor: vConstructor,
	}
}
