package client

import (
	"errors"
	"fmt"

	"github.com/tigera/libcalico-go/lib/backend"
	"github.com/tigera/libcalico-go/lib/common"
)

type allocationHandle struct {
	backend.IPAMHandle
}

func (h allocationHandle) incrementBlock(blockCidr common.IPNet, num int) int {
	blockId := blockCidr.String()
	newNum := num
	if val, ok := h.Block[blockId]; ok {
		// An entry exists for this block, increment the number
		// of allocations.
		newNum = val + num
	}
	h.Block[blockId] = newNum
	return newNum
}

func (h allocationHandle) decrementBlock(blockCidr common.IPNet, num int) (*int, error) {
	blockId := blockCidr.String()
	if current, ok := h.Block[blockId]; !ok {
		// This entry doesn't exist.
		errStr := fmt.Sprintf("Tried to decrement block %s by %s but it isn't linked to handle %s", blockId, num, h.HandleID)
		return nil, errors.New(errStr)
	} else {
		newNum := current - num
		if newNum < 0 {
			errStr := fmt.Sprintf("Tried to decrement block %s by %s but it only has %s addresses on handle %s", blockId, num, current, h.HandleID)
			return nil, errors.New(errStr)
		}

		if newNum == 0 {
			delete(h.Block, blockId)
		} else {
			h.Block[blockId] = newNum
		}
		return &newNum, nil
	}
}

func (h allocationHandle) empty() bool {
	return len(h.Block) == 0
}
