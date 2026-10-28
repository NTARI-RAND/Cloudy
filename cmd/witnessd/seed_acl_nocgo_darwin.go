//go:build !cgo

package main

import (
	"errors"
	"os"
)

func checkSeedACL(_ *os.File) error {
	return errors.New("-seed-file requires a cgo-enabled macOS build to check ACLs; refusing unchecked access")
}
