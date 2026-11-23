//go:build !darwin && !linux

package main

import (
	"errors"
	"os"
)

func openSeedFile(_ string) (*os.File, error) {
	return nil, errors.New("-seed-file permission checks are supported only on Linux and macOS; refusing unchecked access")
}
