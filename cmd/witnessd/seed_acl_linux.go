package main

import "os"

// Linux POSIX ACL permissions are bounded by the group-class mode mask,
// already required to be zero by openSeedFile.
func checkSeedACL(_ *os.File) error { return nil }
