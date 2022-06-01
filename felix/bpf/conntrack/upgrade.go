// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package conntrack

import (
	"fmt"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/cachingmap"
	v2 "github.com/projectcalico/calico/felix/bpf/conntrack/v2"
	v3 "github.com/projectcalico/calico/felix/bpf/conntrack/v3"

	"os"
	"strconv"
	"time"
)

// Key for conversionFns Map.
type conversionKey struct {
	from int
	to   int
}

// Map of conversion functions. Whenever there is a version
// update, add an entry in this map to convert values from
// previous version to the new version.
var conversionFns = map[conversionKey]func([]byte) ([]byte, error) {
	conversionKey{from: 2, to: 3}: convertValueFromV2ToV3,
}

// convertValueFromV2ToV3 converts conntrack value in version 2
// to conntrack value version 3.
func convertValueFromV2ToV3(value []byte) ([]byte, error) {
	// Incoming value is of version 2.
	var valueV2 v2.Value
	var valueV3 v3.Value
	var err error
	copy(valueV2[0:v2.ValueSize], value[0:v2.ValueSize])

	created := time.Duration(valueV2.Created())
	lastSeen := time.Duration(valueV2.LastSeen())
	ctType := valueV2.Type()
	flags := valueV2.Flags()
	switch ctType {
	case TypeNormal, TypeNATReverse:
		data := valueV2.Data()
		v3LegAB := v3.Leg{
			Bytes:       0,
			Packets:     0,
			Seqno:       data.A2B.Seqno,
			SynSeen:     data.A2B.SynSeen,
			AckSeen:     data.A2B.AckSeen,
			FinSeen:     data.A2B.FinSeen,
			RstSeen:     data.A2B.RstSeen,
			Whitelisted: data.A2B.Whitelisted,
			Opener:      data.A2B.Opener,
			Ifindex:     data.A2B.Ifindex,
		}
		v3LegBA := v3.Leg{
			Bytes:       0,
			Packets:     0,
			Seqno:       data.B2A.Seqno,
			SynSeen:     data.B2A.SynSeen,
			AckSeen:     data.B2A.AckSeen,
			FinSeen:     data.B2A.FinSeen,
			RstSeen:     data.B2A.RstSeen,
			Whitelisted: data.B2A.Whitelisted,
			Opener:      data.B2A.Opener,
			Ifindex:     data.B2A.Ifindex,
		}
		if ctType == TypeNormal {
			valueV3 = v3.NewValueNormal(created, lastSeen, flags, v3LegAB, v3LegBA)
		} else {
			valueV3 = v3.NewValueNATReverse(created, lastSeen, flags, v3LegAB, v3LegBA, data.TunIP, data.OrigDst, data.OrigPort)
			valueV3.SetOrigSport(data.OrigSPort)
		}
	case TypeNATForward:
		revKey := valueV2.ReverseNATKey()
		NATSport := valueV2.NATSPort()
		v3RevKey := v3.NewKey(revKey.Proto(), revKey.AddrA(), revKey.PortA(), revKey.AddrB(), revKey.PortB())
		valueV3 = v3.NewValueNATForward(created, lastSeen, flags, v3RevKey)
		valueV3.SetNATSport(NATSport)
	default:
		err = fmt.Errorf("invalid conntrack type")
	}
	return valueV3.AsBytes(), err

}

func getMapParams(version int) bpf.MapParameters {
	switch version {
	case 3:
		return v3.MapParams
	case 2:
		return v2.MapParams
	}
	return v2.MapParams
}

// Get the previous version of the map
func getPrevVersion(latest int, prev *int) error {
	for i := latest - 1; i >= 2; i-- {
		filename := "/sys/fs/bpf/tc/globals/cali_v4_ct" + strconv.Itoa(i)
		_, err := os.Stat(filename)
		if err == nil {
			*prev = i
			return nil
		} else if os.IsNotExist(err) {
			continue
		} else {
			return err
		}
	}
	return nil
}

// Upgrade does the actual upgrade by iterating through the
// k,v pairs in the old map, applying the conversion functions
// and writing the new k,v pair to the newly created map.
func (m *MultiVersionMap) Upgrade() error {
	mc := &bpf.MapContext{}
	from := 0
	to := CurrentMapVersion
	err := getPrevVersion(to, &from)
	if err != nil {
		return err
	} else if from == 0 {
		return nil
	}
	toBpfMap := m.ctMap
	toCachingMap := cachingmap.New(MapParams, toBpfMap)
	if toCachingMap == nil {
		return fmt.Errorf("error creating caching map")
	}
	err = toCachingMap.LoadCacheFromDataplane()
	if err != nil {
		return err
	}

	fromMapParams := getMapParams(from)
	fromBpfMap := mc.NewPinnedMap(fromMapParams)
	err = fromBpfMap.EnsureExists()
	if err != nil {
		return fmt.Errorf("error creating a handle for the old map")
	}

	defer fromBpfMap.(*bpf.PinnedMap).Close()
	fromCachingMap := cachingmap.New(fromMapParams, fromBpfMap)
	if fromCachingMap == nil {
		return fmt.Errorf("error creating caching map")
	}
	err = fromCachingMap.LoadCacheFromDataplane()
	if err != nil {
		return err
	}
	fromCachingMap.IterDataplaneCache(func(k, v []byte) {
		tmp := v[:]
		for i := from; i < to; i++ {
			key := conversionKey{from: i, to: i + 1}
			f := conversionFns[key]
			tmp, err = f(tmp)
			if err != nil {
				err =  fmt.Errorf("error upgrading conntrack map %w", err)
				break
			}
		}
		toCachingMap.SetDesired(k, tmp)
	})

	if err != nil {
		return err
	}

	err = toCachingMap.ApplyAllChanges()
	if err != nil {
		return fmt.Errorf("error upgrading new map %w", err)
	}
	return nil
}
