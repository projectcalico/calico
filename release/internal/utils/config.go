package utils

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	// ProductName is the name of the product.
	ProductName = "calico"

	// ProductCode is the code of the product.
	ProductCode = "os"
)

// DisplayProductName returns the product name in title case.
func DisplayProductName() string {
	return cases.Title(language.English).String(ProductName)
}
