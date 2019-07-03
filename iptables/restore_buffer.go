// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"bytes"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// RestoreInputBuilder builds an byte slice for use as input to iptables-restore.
//
// Operations must be done inside a per-table transaction.
//
// Example:
//
//     buf.StartTransaction("filter")
//     buf.WriteForwardReference("cali-chain-name")
//     buf.WriteLine("-A cali-chain-name ...")
//     buf.EndTransaction()
//     bytes = buf.GetBytesAndInvalidate()
//     <write bytes to iptables-restore stdin>
//     buf.Reset()
//
// Transactions are ignored completely if there are no writes between the StartTransaction()
// and EndTransaction() calls.
type RestoreInputBuilder struct {
	buf                   bytes.Buffer
	currentTableName      string
	NumLinesInTransaction int
}

// Empty returns true if there is nothing in the buffer (i.e. all the transactions stored in the buffer were no-ops).
func (b *RestoreInputBuilder) Empty() bool {
	return b.buf.Len() == 0
}

// Reset the builder completely, any pending transaction is discarded.
func (b *RestoreInputBuilder) Reset() {
	b.buf.Reset()
	b.currentTableName = ""
	b.NumLinesInTransaction = 0
}

// StartTransaction opens a new transaction context for the named table.
// Panics if there is already a transaction in progress.
func (b *RestoreInputBuilder) StartTransaction(tableName string) {
	if b.currentTableName != "" {
		log.Panic("StartTransaction() called without ending previous transaction.")
	}
	b.currentTableName = tableName
}

// EndTransaction ends the open transaction, if the transaction was non-empty, writes a COMMIT.
// Resets the transaction tracking state.  Panics if there was no open transaction.
func (b *RestoreInputBuilder) EndTransaction() {
	if b.currentTableName == "" {
		log.Panic("EndTransaction() called without active transaction.")
	}
	if b.NumLinesInTransaction > 0 {
		b.writeFormattedLine("COMMIT")
	}
	b.currentTableName = ""
	b.NumLinesInTransaction = 0
}

// writeFormattedLine writes a line to the internal buffer, appending a new line.
func (b *RestoreInputBuilder) writeFormattedLine(format string, args ...interface{}) {
	_, err := fmt.Fprintf(&b.buf, format, args...)
	if err != nil {
		log.WithError(err).Panic("Failed to write to in-memory buffer")
	}
	b.buf.WriteString("\n")
}

// maybeWriteTransactionOpener ensures that the transaction opening line has been written.
// Panics if there is no open transaction.
func (b *RestoreInputBuilder) maybeWriteTransactionOpener() {
	if b.currentTableName == "" {
		log.Panic("maybeWriteTransactionOpener() called without active transaction.")
	}
	if b.NumLinesInTransaction == 0 {
		b.writeFormattedLine("*%s", b.currentTableName)
	}
}

// WriteForwardReference writes a "forward reference" for the given chain name. A forward reference is an instruction
// that tells iptables to ensure that the given chain exists and that it is empty. Panics if there is no open
// transaction.
func (b *RestoreInputBuilder) WriteForwardReference(chainName string) {
	b.maybeWriteTransactionOpener()
	b.writeFormattedLine(":%s - -", chainName)
	b.NumLinesInTransaction++
}

// WriteLine writes a line of iptables instructions to the buffer.  Intended for writing the actual rules.
// Panics if there is no open transaction.
func (b *RestoreInputBuilder) WriteLine(line string) {
	b.maybeWriteTransactionOpener()
	b.writeFormattedLine(line)
	b.NumLinesInTransaction++
}

// GetBytesAndInvalidate returns the contents of the buffer.  For performance, this is a direct reference to the
// data rather than a copy.  Should be called after EndTransaction; panics if there is a still-open transaction.
//
// After calling GetBytesAndInvalidate(), the only valid method to call on this struct is Reset().  The returned slice
// should not be modified and it is only valid until Reset() is called.
func (b *RestoreInputBuilder) GetBytesAndInvalidate() []byte {
	if b.currentTableName != "" {
		log.Panic("GetBytesAndInvalidate() called inside transaction.")
	}
	return b.buf.Next(b.buf.Len())
}
