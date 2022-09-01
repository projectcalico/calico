// Copyright (c) 2022  All rights reserved.

package utils

import (
	"os"

	. "github.com/onsi/gomega"
)

func PatchEnv(key, value string) (unpatch func(), err error) {
	oldKC, oldKCSet := os.LookupEnv(key)
	err = os.Setenv(key, value)
	if err != nil {
		return
	}
	if oldKCSet {
		unpatch = func() {
			Expect(os.Setenv(key, oldKC)).NotTo(HaveOccurred())
		}
	} else {
		unpatch = func() {
			Expect(os.Unsetenv(key)).NotTo(HaveOccurred())
		}
	}
	return
}
