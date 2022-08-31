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

package syncproto

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"testing"

	. "github.com/onsi/gomega"
)

const cannedEnvelopeWithHello = "Iv+BAwEBCEVudmVsb3BlAf+CAAEBAQdNZXNzYWdlARAAAAD/jP+CATtnaXRodWIuY29tL3Byb2plY3R" +
	"jYWxpY28vdHlwaGEvcGtnL3N5bmNwcm90by5Nc2dDbGllbnRIZWxsb/+DAwEBDk1zZ0NsaWVudEhlbGxvAf+EAAEEAQhIb3N0bmFtZQEMAA" +
	"EESW5mbwEMAAEHVmVyc2lvbgEMAAEKU3luY2VyVHlwZQEMAAAAKv+EJgEIaG9zdG5hbWUBBGluZm8BB3ZlcnNpb24BCnN5bmNlcnR5cGUAAA=="

var envelope = Envelope{
	Message: MsgClientHello{
		Hostname:   "hostname",
		Info:       "info",
		Version:    "version",
		SyncerType: "syncertype",
	},
}

// TestDecodeCanned is intended to test back compatibility of our gob encoding.  The canned data should decode
// correctly even for newer versions of gob and even after refactoring/moving code around.  If this test starts
// failing, either we've made a back-incompatible change or the gob library has.
func TestDecodeCanned(t *testing.T) {
	RegisterTestingT(t)

	var b bytes.Buffer
	_, err := b.WriteString(cannedEnvelopeWithHello)
	Expect(err).NotTo(HaveOccurred())

	b64 := base64.NewDecoder(base64.StdEncoding, &b)
	p := make([]byte, len(cannedEnvelopeWithHello))
	n, err := b64.Read(p)
	Expect(err).NotTo(HaveOccurred())

	b.Reset()
	b.Write(p[:n])

	dec := gob.NewDecoder(&b)
	var env Envelope
	err = dec.Decode(&env)
	Expect(err).NotTo(HaveOccurred())
	Expect(env).To(Equal(envelope))
}

// TestEncodeCanned was used to generate the canned data up above.
func TestEncodeCanned(t *testing.T) {
	RegisterTestingT(t)
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(&envelope)
	Expect(err).NotTo(HaveOccurred())

	var b2 bytes.Buffer
	b64 := base64.NewEncoder(base64.StdEncoding, &b2)
	_, err = b64.Write(b.Bytes())
	Expect(err).NotTo(HaveOccurred())
	err = b64.Close()
	Expect(err).NotTo(HaveOccurred())

	t.Logf("%q", b2.String())
}
