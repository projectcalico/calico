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
// update, add an entry in this map to convert keys, values from
// previous version to the new version.
var conversionFns = map[conversionKey]func([]byte, []byte) ([]byte, []byte, error){
	conversionKey{from: 2, to: 3}: convertCtFromV2ToV3,
}

// convertValueFromV2ToV3 converts conntrack value in version 2
// to conntrack value version 3.
func convertCtFromV2ToV3(key, value []byte) ([]byte, []byte, error) {
	// Incoming key, value is of version 2.
	var valueV2 v2.Value
	var valueV3 v3.Value

	var keyV2 v2.Key
	var keyV3 v3.Key
	var err error

	copy(valueV2[0:v2.ValueSize], value[0:v2.ValueSize])
	copy(keyV2[0:v2.KeySize], key[0:v2.KeySize])

	keyV3 = v3.NewKey(keyV2.Proto(), keyV2.AddrA(), keyV2.PortA(), keyV2.AddrB(), keyV2.PortB())

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
			valueV3 = v3.NewValueNATReverseSNAT(created, lastSeen, flags, v3LegAB, v3LegBA, data.TunIP, data.OrigDst, data.OrigSrc, data.OrigPort)
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
	return keyV3.AsBytes(), valueV3.AsBytes(), err

}

// Get the previous version of the map
func getOldVersion(latest int, prev *int) error {
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
