package noderelay

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/NTARI-RAND/sohocloud-protocol/identity"
)

// A node registered with a SoHoLINK-style orchestrator is named by a random
// UUID in lowercase canonical form (8-4-4-4-12 hex digits), the form SoHoLINK's
// POST /operators/nodes accepts. A random ID names the machine and nothing
// else: it carries no hostname, owner, or place.

// NewNodeID returns a fresh random (version 4) UUID node ID.
func NewNodeID() (identity.NodeID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return identity.NodeID(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])), nil
}

// ValidNodeID reports whether id is a UUID in lowercase canonical form.
func ValidNodeID(id identity.NodeID) bool {
	s := string(id)
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
				return false
			}
		}
	}
	return true
}

// LoadOrCreateNodeID reads the node's ID from path, creating a fresh one on
// first run, so a machine keeps the same ID across restarts. The file must
// hold exactly one valid node ID.
func LoadOrCreateNodeID(path string) (identity.NodeID, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id, err := NewNodeID()
		if err != nil {
			return "", err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", fmt.Errorf("write node ID: %w", err)
		}
		if _, err := f.WriteString(string(id) + "\n"); err != nil {
			f.Close()
			return "", fmt.Errorf("write node ID: %w", err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("write node ID: %w", err)
		}
		return id, nil
	}
	if err != nil {
		return "", fmt.Errorf("read node ID: %w", err)
	}
	id := identity.NodeID(strings.TrimSpace(string(data)))
	if !ValidNodeID(id) {
		return "", fmt.Errorf("node ID file %s: want one lowercase UUID; if it is empty or cut short (an interrupted first run), that ID was never registered and the file is safe to delete", path)
	}
	return id, nil
}
