package storage

import (
	"fmt"
	"io"
	"sort"
	"time"
)

// FetchStep schedules one shard retrieval: which shard, and how long after
// the plan starts to request it.
type FetchStep struct {
	Index int // shard index into the object's manifest order
	Delay time.Duration
}

// FetchPlan is the retrieval half of countermeasure 2: shards of one object
// are fetched in a random order with independent random delays spread over
// window, so the hosts holding them never observe the tight, ordered burst
// that would regroup the object for an observer comparing notes. The plan is
// deterministic under injected entropy for tests; production passes
// crypto/rand and its chosen latency window.
//
// The steps are returned sorted by Delay — execution order — while Index
// carries the shuffled shard identity.
func FetchPlan(shardCount int, window time.Duration, entropy io.Reader) ([]FetchStep, error) {
	if shardCount < 1 {
		return nil, fmt.Errorf("storage: shardCount must be >= 1, got %d", shardCount)
	}
	if window < 0 {
		return nil, fmt.Errorf("storage: window must be >= 0, got %v", window)
	}
	steps := make([]FetchStep, shardCount)
	for i := range steps {
		steps[i].Index = i
		if window > 0 {
			j, err := uniformInt(entropy, int(window))
			if err != nil {
				return nil, err
			}
			steps[i].Delay = time.Duration(j)
		}
	}
	sort.Slice(steps, func(a, b int) bool {
		if steps[a].Delay != steps[b].Delay {
			return steps[a].Delay < steps[b].Delay
		}
		return steps[a].Index < steps[b].Index
	})
	return steps, nil
}
