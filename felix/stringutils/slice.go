// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

package stringutils

func FirstIndexInSlice(slice []string, val string) int {
	for i := range slice {
		if val == slice[i] {
			return i
		}
	}
	return -1
}

func InSlice(slice []string, val string) bool {
	return FirstIndexInSlice(slice, val) != -1
}

func RemoveValue(slice []string, val string) []string {
	found := false
	for i := range slice {
		if found {
			slice[i-1] = slice[i]
		} else {
			found = slice[i] == val
		}
	}
	if found {
		return slice[:len(slice)-1]
	}
	return slice
}
