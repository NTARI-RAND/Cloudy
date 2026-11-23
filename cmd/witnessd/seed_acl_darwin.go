//go:build cgo

package main

/*
#include <sys/acl.h>
*/
import "C"

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// Darwin mode bits omit ACL read grants. Query the opened descriptor directly;
// reject all extended ACLs rather than interpret inherited grants.
func checkSeedACL(file *os.File) error {

	acl, err := C.acl_get_fd_np(C.int(file.Fd()), C.ACL_TYPE_EXTENDED)
	if acl == nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return errors.New("cannot verify -seed-file macOS ACL")
	}
	defer func() { _, _ = C.acl_free(unsafe.Pointer(acl)) }()
	var entry C.acl_entry_t
	status, err := C.acl_get_entry(acl, C.ACL_FIRST_ENTRY, &entry)
	if status == 0 {
		return errors.New("-seed-file must have no extended ACL; remove grants with chmod -N")
	}
	if errors.Is(err, syscall.EINVAL) {
		return nil
	} // Valid ACL with no first entry.
	return errors.New("cannot inspect -seed-file macOS ACL")
}
