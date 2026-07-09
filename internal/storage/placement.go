package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Host is a candidate storage node as the placement layer sees it: an
// opaque node identifier and its owning member. Placement never sees who
// the DATA belongs to — it decorrelates, it does not correlate.
type Host struct {
	ID    string
	Owner string
}

var (
	// ErrInsufficientHosts means the hard distinct-host rule cannot be met.
	// Placement fails closed: it never doubles up shards on a host to make
	// an object "fit", because that would let one host regroup an object.
	ErrInsufficientHosts = errors.New("storage: fewer hosts than shards")
)

// PlaceShards assigns each shard index to a host under countermeasure 2's
// placement rules:
//
//   - HARD: no host receives two shards of the same object. One curious
//     host can then never hold enough co-located ciphertext to regroup an
//     object, and (with parity, later) never enough to matter.
//   - SOFT: distinct owners are preferred while any remain unused, so a
//     member operating several nodes is not silently treated as several
//     independent parties.
//
// The host order is shuffled from entropy so placement itself carries no
// pattern (same inputs, different entropy → different assignment). Returns
// a slice where element i is the host for shard i.
func PlaceShards(shardCount int, hosts []Host, entropy io.Reader) ([]Host, error) {
	if shardCount < 1 {
		return nil, fmt.Errorf("storage: shardCount must be >= 1, got %d", shardCount)
	}
	if len(hosts) < shardCount {
		return nil, fmt.Errorf("%w: %d hosts for %d shards", ErrInsufficientHosts, len(hosts), shardCount)
	}
	shuffled := make([]Host, len(hosts))
	copy(shuffled, hosts)
	if err := shuffle(shuffled, entropy); err != nil {
		return nil, err
	}

	assigned := make([]Host, 0, shardCount)
	usedHost := make(map[string]bool, shardCount)
	usedOwner := make(map[string]bool, shardCount)

	// Pass 1: distinct host AND distinct owner.
	for _, h := range shuffled {
		if len(assigned) == shardCount {
			break
		}
		if usedHost[h.ID] || usedOwner[h.Owner] {
			continue
		}
		assigned = append(assigned, h)
		usedHost[h.ID] = true
		usedOwner[h.Owner] = true
	}
	// Pass 2: distinct host only, once owners are exhausted.
	for _, h := range shuffled {
		if len(assigned) == shardCount {
			break
		}
		if usedHost[h.ID] {
			continue
		}
		assigned = append(assigned, h)
		usedHost[h.ID] = true
	}
	if len(assigned) != shardCount {
		// Duplicate host IDs in the candidate list can starve pass 2.
		return nil, fmt.Errorf("%w: %d distinct hosts for %d shards", ErrInsufficientHosts, len(usedHost), shardCount)
	}
	return assigned, nil
}

// shuffle is a Fisher–Yates over entropy so tests can be deterministic and
// production uses crypto/rand.
func shuffle(hosts []Host, entropy io.Reader) error {
	for i := len(hosts) - 1; i > 0; i-- {
		j, err := uniformInt(entropy, i+1)
		if err != nil {
			return err
		}
		hosts[i], hosts[j] = hosts[j], hosts[i]
	}
	return nil
}

// uniformInt draws an unbiased integer in [0, n) via rejection sampling.
func uniformInt(entropy io.Reader, n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("storage: uniformInt bound must be positive, got %d", n)
	}
	max := ^uint64(0)
	limit := max - max%uint64(n)
	var buf [8]byte
	for {
		if _, err := io.ReadFull(entropy, buf[:]); err != nil {
			return 0, fmt.Errorf("storage: reading entropy: %w", err)
		}
		v := binary.BigEndian.Uint64(buf[:])
		if v < limit {
			return int(v % uint64(n)), nil
		}
	}
}
