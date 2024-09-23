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

// RestoreInputBuilder builds a byte slice for use as input to iptables-restore.
//
// Operations must be done inside a per-table transaction.
//
// Example:
//
//	buf.Reset() // Reset the buffer, if needed.
//	buf.StartTransaction("filter")
//	buf.WriteForwardReference("cali-chain-name")
//	buf.WriteLine("-A cali-chain-name ...")
//	buf.EndTransaction()
//	bytes = buf.GetBytesAndReset()
//	<write bytes to iptables-restore stdin>
//
// Transactions are ignored completely if there are no writes between the StartTransaction()
// and EndTransaction() calls.
type RestoreInputBuilder struct {
	buf              bytes.Buffer
	currentTableName string
	txnOpenerWritten bool
	NumLinesWritten  counter
}

// Empty returns true if there is nothing in the buffer (i.e. all the transactions stored in the buffer were no-ops).
func (b *RestoreInputBuilder) Empty() bool {
	return b.buf.Len() == 0
}

// Reset the builder completely, any pending transaction is discarded.
func (b *RestoreInputBuilder) Reset() {
	b.buf.Reset()
	b.currentTableName = ""
	b.txnOpenerWritten = false
}

// StartTransaction opens a new transaction context for the named table.
// Panics if there is already a transaction in progress.
func (b *RestoreInputBuilder) StartTransaction(tableName string) {
	if b.currentTableName != "" {
		log.Panic("StartTransaction() called without ending previous transaction.")
	}
	b.currentTableName = tableName
	b.txnOpenerWritten = false
}

// EndTransaction ends the open transaction, if the transaction was non-empty, writes a COMMIT.
// Resets the transaction tracking state.  Panics if there was no open transaction.
func (b *RestoreInputBuilder) EndTransaction() {
	if b.currentTableName == "" {
		log.Panic("EndTransaction() called without active transaction.")
	}
	if b.txnOpenerWritten {
		b.writeFormattedLine("COMMIT")
	}
	b.currentTableName = ""
}

// writeFormattedLine writes a line to the internal buffer, appending a new line.
func (b *RestoreInputBuilder) writeFormattedLine(format string, args ...interface{}) {
	_, err := fmt.Fprintf(&b.buf, format, args...)
	if err != nil {
		log.WithError(err).Panic("Failed to write to in-memory buffer")
	}
	b.buf.WriteString("\n")
	if b.NumLinesWritten != nil {
		b.NumLinesWritten.Inc()
	}
}

// maybeWriteTransactionOpener ensures that the transaction opening line has been written.
// Panics if there is no open transaction.
func (b *RestoreInputBuilder) maybeWriteTransactionOpener() {
	if b.currentTableName == "" {
		log.Panic("maybeWriteTransactionOpener() called without active transaction.")
	}
	if !b.txnOpenerWritten {
		b.writeFormattedLine("*%s", b.currentTableName)
		b.txnOpenerWritten = true
	}
}

// WriteForwardReference writes a "forward reference" for the given chain name. A forward reference is an instruction
// that tells iptables to ensure that the given chain exists and that it is empty. Panics if there is no open
// transaction.
func (b *RestoreInputBuilder) WriteForwardReference(chainName string) {
	b.maybeWriteTransactionOpener()
	b.writeFormattedLine(":%s - -", chainName)
}

// WriteLine writes a line of iptables instructions to the buffer.  Intended for writing the actual rules.
// Panics if there is no open transaction.
func (b *RestoreInputBuilder) WriteLine(line string) {
	b.maybeWriteTransactionOpener()
	b.writeFormattedLine("%s", line)
}

// GetBytesAndReset returns the contents of the buffer and, as a side effect, resets the buffer.  For performance,
// this is a direct reference to the data rather than a copy.  The returned slice is only valid until the next
// write operation on the builder.  Should be called after EndTransaction; panics if there is a still-open transaction.
func (b *RestoreInputBuilder) GetBytesAndReset() []byte {
	if b.currentTableName != "" {
		log.Panic("GetBytesAndReset() called inside transaction.")
	}
	buf := b.buf.Next(b.buf.Len())
	b.Reset()
	return buf
}

type counter interface {
	Inc()
}
