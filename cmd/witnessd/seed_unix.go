//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"syscall"
)

// Inspect the opened descriptor so permission checks and reads name the same
// file. Nonblocking/no-follow opens reject FIFOs and final-component symlinks.
func openSeedFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open -seed-file (regular file required; symlinks refused)")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		_ = file.Close()
		return nil, errors.New("-seed-file must be a regular owner-only file (chmod 600)")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, errors.New("-seed-file must be owned by the current user")
	}
	if err := checkSeedACL(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
