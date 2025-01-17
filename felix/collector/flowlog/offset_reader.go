// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package flowlog

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// LogOffset determines whether the logs are being stalled in the external processing pipeline
// It can read the offsets and determine if the pipeline is stalled and estimate the increase
// factor for aggregation
type LogOffset interface {
	Read() Offsets
	IsBehind(offsets Offsets) bool
	GetIncreaseFactor(offsets Offsets) int
}

// Offsets type is a (key,value) pair set as the log file name and the offset
type Offsets map[string]int64

// OffsetReader reads the offset between the current position of the external processing pipeline
// and current position of the log file. It returns a map with (key,value) set as the log file name
// the offset
type OffsetReader interface {
	Read() Offsets
}

// NoOpLogOffset will never mark logs as being stalled
type NoOpLogOffset struct{}

func (noOp *NoOpLogOffset) Read() Offsets {
	return Offsets{}
}

func (noOp *NoOpLogOffset) IsBehind(offsets Offsets) bool {
	return false
}

func (noOp *NoOpLogOffset) GetIncreaseFactor(offsets Offsets) int {
	return 0
}

type rangeLogOffset struct {
	reader    OffsetReader
	threshold int64
}

// NewRangeLogOffset creates a new rangeLogOffset. rangeLogOffset reads Offsets and it compares the values to be within
// the range of interval [0, threshold). Any negative offset or any offset above the threshold will mark the fact that logs
// are being stalled in the external processing pipeline
func NewRangeLogOffset(offsetReader OffsetReader, threshold int64) *rangeLogOffset {
	if threshold <= 0 {
		panic(fmt.Sprintf("Invalid parameter for threshold %d. Any value above zero is accepted", threshold))
	}
	return &rangeLogOffset{offsetReader, threshold}
}

type FluentDLogOffsetReader struct {
	regExp       *regexp.Regexp
	positionFile string
}

const pattern = `^([^\t]+)\t([0-9a-fA-F]+)\t([0-9a-fA-F]+)`

// unwatched position represent the value that FluentD writes for any files and it no longer being monitored
// please see https://github.com/fluent/fluentd/blob/6ef77be211d33c06c8602f71daa47910822e042e/lib/fluent/plugin/in_tail.rb#L392
const unwatchedPosition = "ffffffffffffffff"

var posFilePattern = regexp.MustCompile(pattern)

// NewFluentDLogOffsetReader creates a new FluentDLogOffsetReader. FluentDLogOffsetReader reads Offsets stored by
// FluentD in the position file and compares than with the actual size of the logfile. The position file written by
// FluentD will have one entry for each of the log files that is reading from. Each line from the position file will
// have the following format: {file_path}\t{position_in_file_as_hex}\t{inode_of_the_file_as_hex}
func NewFluentDLogOffsetReader(positionFile string) *FluentDLogOffsetReader {
	return &FluentDLogOffsetReader{posFilePattern, positionFile}
}

func (fluentD *rangeLogOffset) Read() Offsets {
	return fluentD.reader.Read()
}

func (fluentD *rangeLogOffset) IsBehind(offsets Offsets) bool {
	for _, v := range offsets {
		if v < 0 || v >= fluentD.threshold {
			return true
		}
	}
	return false
}

func (fluentD *rangeLogOffset) GetIncreaseFactor(offsets Offsets) int {
	var maxFactor = int(MinAggregationLevel)

	for _, v := range offsets {
		if v < 0 {
			return int(MaxAggregationLevel)
		}
		if v >= fluentD.threshold {
			var factor = int(v / fluentD.threshold)
			if factor > maxFactor {
				maxFactor = factor
			}
		}
	}

	if maxFactor > int(MaxAggregationLevel) {
		maxFactor = int(MaxAggregationLevel)
	}
	return maxFactor
}

func (fluentD *FluentDLogOffsetReader) Read() Offsets {
	var offsets = Offsets{}
	log.Debugf("Reading last position from %s", fluentD.positionFile)
	fi, err := os.Open(fluentD.positionFile)
	if err != nil {
		log.Warnf("Could not open file %s due to %s", fluentD.positionFile, err)
		return offsets
	}
	defer func() {
		err := fi.Close()
		if err != nil {
			log.Warn("Could not close file", err)
		}
	}()

	scanner := bufio.NewScanner(fi)
	for scanner.Scan() {
		line := scanner.Text()
		log.Debugf("Read line %s", line)
		matched := fluentD.regExp.FindStringSubmatch(line)
		if len(matched) != 4 {
			log.Debugf("No match found the line %s", line)
			continue
		}
		log.Debugf("Found matching line %s", line)

		var value, ok = offset(matched[2], matched[1])
		if ok {
			offsets[matched[1]] = value
		}
	}

	return offsets
}

func offset(hexOffset string, filePath string) (int64, bool) {
	var currentSize int64

	if hexOffset == unwatchedPosition {
		log.Warnf("File %s is not watched and will be ignored", filePath)
		return 0, false
	}

	offset, err := strconv.ParseInt(hexOffset, 16, 64)
	if err != nil {
		log.Warnf("Could not decode offset %s due to %s", hexOffset, err)
		return 0, false
	}
	fi, err := os.Stat(filePath)
	if err != nil {
		log.Warnf("Could not stat file %s due to %s", filePath, err)
		return 0, false
	}
	currentSize = fi.Size()

	log.Debugf("Position is set at %d for file %s with size %d", offset, filePath, currentSize)
	return currentSize - offset, true
}
