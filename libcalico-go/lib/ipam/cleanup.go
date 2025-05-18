// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package ipam

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// CleanupBlocksForRemovedNodes cleans up IPAM blocks that have affinity to nodes
// that are no longer in the cluster.
// activeNodes: List of active node names in the cluster
// force: If true, will delete blocks even if they have active IP allocations
// Returns: Number of blocks cleaned up and any error encountered
func (c ipamClient) CleanupBlocksForRemovedNodes(ctx context.Context, activeNodes []string, force bool) (int, error) {
	logCtx := log.WithFields(log.Fields{
		"activeNodes": len(activeNodes),
		"force":       force,
	})
	logCtx.Info("Cleaning up IPAM blocks for removed nodes")

	// Get all blocks
	blocks, err := c.blockReaderWriter.listBlocks(ctx, "")
	if err != nil {
		return 0, err
	}

	// Create a map of active nodes for efficient lookup
	activeNodeMap := map[string]bool{}
	for _, node := range activeNodes {
		activeNodeMap[node] = true
	}

	// Find blocks with affinity to non-existent nodes
	var cleanupBlocks []*model.KVPair
	for _, b := range blocks.KVPairs {
		// Create a local copy of the block so we can safely take its address
		block := b
		if affinity := block.Value.(*model.AllocationBlock).Affinity; affinity != nil {
			// Parse affinity to get node name
			parts := strings.Split(*affinity, ":")
			if len(parts) != 2 {
				// Skip blocks with malformed affinity
				logCtx.WithField("affinity", *affinity).Debug("Skipping block with malformed affinity")
				continue
			}

			affinityType, nodeName := parts[0], parts[1]

			// Skip if not host affinity or if node still exists
			if affinityType != "host" || activeNodeMap[nodeName] {
				continue
			}

			// If force is false, only clean up empty blocks
			blockObj := allocationBlock{block.Value.(*model.AllocationBlock)}
			if !force && !blockObj.empty() {
				logCtx.WithFields(log.Fields{
					"block":        block.Key.(model.BlockKey).CIDR.String(),
					"node":         nodeName,
					"allocatedIPs": blockObj.inUseIPs(),
				}).Info("Skipping non-empty block because force is false")
				continue
			}

			// Add the block to our cleanup list
			cleanupBlocks = append(cleanupBlocks, block)
		}
	}

	// If no blocks to clean up, return early
	if len(cleanupBlocks) == 0 {
		logCtx.Info("No orphaned blocks found")
		return 0, nil
	}

	logCtx.WithField("blocksToClean", len(cleanupBlocks)).Info("Found orphaned blocks to clean")

	// Delete the blocks in parallel with limited concurrency
	workers := runtime.GOMAXPROCS(0)
	if workers > 10 {
		workers = 10 // Limit max concurrent workers
	}

	sem := semaphore.NewWeighted(int64(workers))
	var cleanedCount int32 = 0
	var errorMutex sync.Mutex
	var lastError error

	for _, block := range cleanupBlocks {
		// Check for context cancellation
		if ctx.Err() != nil {
			return int(cleanedCount), ctx.Err()
		}

		if err := sem.Acquire(ctx, 1); err != nil {
			// Context canceled or deadline exceeded
			return int(cleanedCount), err
		}

		go func(b *model.KVPair) {
			defer sem.Release(1)

			blockCIDR := b.Key.(model.BlockKey).CIDR
			affinity := b.Value.(*model.AllocationBlock).Affinity
			blockLogCtx := logCtx.WithFields(log.Fields{
				"blockCIDR": blockCIDR.String(),
				"affinity":  *affinity,
			})
			blockLogCtx.Info("Cleaning up orphaned block")

			// Try to delete the block directly
			err := c.blockReaderWriter.deleteBlock(ctx, b)
			if err != nil {
				if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
					// Block already deleted, that's fine
					blockLogCtx.Info("Block already deleted, skipping")
				} else {
					blockLogCtx.WithError(err).Error("Failed to delete block")
					// Save the last error
					errorMutex.Lock()
					lastError = err
					errorMutex.Unlock()
					return
				}
			}

			atomic.AddInt32(&cleanedCount, 1)
			blockLogCtx.Info("Successfully deleted orphaned block")
		}(block)
	}

	// Wait for all workers to finish
	if err := sem.Acquire(ctx, int64(workers)); err != nil {
		return int(cleanedCount), err
	}

	// If we had errors during processing, return the last one
	if lastError != nil {
		return int(cleanedCount), lastError
	}

	logCtx.WithField("cleanedCount", cleanedCount).Info("Successfully cleaned up orphaned blocks")
	return int(cleanedCount), nil
}
