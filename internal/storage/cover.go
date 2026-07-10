package storage

import (
	"fmt"
	"io"
	"math"
	"time"
)

// CoverScheduler is countermeasure 4: probes toward a host fire on a
// memoryless randomized cadence (exponential inter-arrivals) that runs
// whether or not the member ever reads, and latency-tolerant reads ride the
// next probe slot instead of firing on demand. From the host's chair every
// arrival is "another routine probe": interest is indistinguishable from
// upkeep, because reads do not add events or bend the rhythm — they occupy
// slots the rhythm was going to spend anyway.
//
// Exponential spacing is deliberate: a Poisson process is memoryless, so
// observing any history of arrivals says nothing about when the next one
// comes, and slot-riding reads inherit that property. Inter-arrivals are
// clamped to [mean/20, mean*10] so entropy edge cases cannot produce a
// zero-delay burst or an unbounded silence.
//
// Urgent reads that cannot wait for a slot MUST bypass the scheduler and
// are a named residual leak (doc.go) — the choice between latency and
// legibility belongs to the caller, per member sovereignty.
type CoverScheduler struct {
	mean    time.Duration
	entropy io.Reader
	nextAt  time.Time
}

// NewCoverScheduler starts a cadence with the given mean inter-probe
// interval, beginning at now. Production passes crypto/rand; tests inject
// deterministic entropy.
func NewCoverScheduler(mean time.Duration, now time.Time, entropy io.Reader) (*CoverScheduler, error) {
	entropy = randOr(entropy)
	if mean <= 0 {
		return nil, fmt.Errorf("storage: mean interval must be positive, got %v", mean)
	}
	s := &CoverScheduler{mean: mean, entropy: entropy}
	first, err := s.interval()
	if err != nil {
		return nil, err
	}
	s.nextAt = now.Add(first)
	return s, nil
}

// NextProbe reports when the next probe fires. The caller (cloudyd's audit
// loop) sends a table challenge at that instant — real audit and cover
// traffic are the same event.
func (s *CoverScheduler) NextProbe() time.Time { return s.nextAt }

// Claim hands the next slot at or after now to a caller — either the audit
// loop firing a routine probe, or a read riding the cadence — and schedules
// the slot after it. Exactly one event happens per slot either way, which
// is the whole point: total arrivals seen by the host follow the same
// process whether the member was reading or not.
func (s *CoverScheduler) Claim(now time.Time) (time.Time, error) {
	slot := s.nextAt
	if slot.Before(now) {
		slot = now
	}
	next, err := s.interval()
	if err != nil {
		return time.Time{}, err
	}
	s.nextAt = slot.Add(next)
	return slot, nil
}

// interval draws one exponential inter-arrival with mean s.mean, clamped.
func (s *CoverScheduler) interval() (time.Duration, error) {
	// Draw u uniform in (0,1]: 64 entropy bits scaled, zero mapped away so
	// math.Log never sees 0.
	v, err := uniformInt(s.entropy, 1<<62)
	if err != nil {
		return 0, err
	}
	u := (float64(v) + 1) / float64(uint64(1)<<62)
	d := time.Duration(-float64(s.mean) * math.Log(u))
	if min := s.mean / 20; d < min {
		d = min
	}
	if max := s.mean * 10; d > max {
		d = max
	}
	return d, nil
}
