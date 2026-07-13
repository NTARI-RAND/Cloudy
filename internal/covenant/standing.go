package covenant

// Standing is the LBTAS read view of one member's reputation: per-category
// distributions, the pooled overall distribution, and the harm count. It is
// built only by Book.Standing; its state is unexported, so it cannot be
// constructed with fabricated counts or serialized through this package's
// types. Deliberately absent, like everywhere else in the package: any mean,
// average, or scalar summary of level VALUES, and any comparison or ordering
// between members.
type Standing struct {
	byCategory map[string]Distribution
	overall    Distribution
}

// Category returns the distribution of admitted assessments about the
// subject under the named category. A category with no assessments — or a
// name outside the vocabulary — yields an empty Distribution with Total
// zero, not an error.
func (s Standing) Category(name string) Distribution {
	return s.byCategory[name]
}

// Overall returns the pooled distribution across all categories: the same
// verdicts as the per-category views, counted once each, in one histogram.
func (s Standing) Overall() Distribution {
	return s.overall
}

// Total returns the number of admitted assessments across all categories —
// the distribution's size. Per LBTAS this is itself a signal (transaction
// volume, and a proxy for time in service), never a denominator for a mean.
func (s Standing) Total() int {
	return s.overall.Total()
}

// Harm returns the count of No Trust (-1) verdicts across all categories.
// This is a per-level count surfaced by name — the never-diluted signal
// LBTAS mandates — NOT a collapse of the distribution: it is exactly
// Overall().Count(LevelNoTrust), raised so a single -1 can never hide
// behind surrounding praise.
func (s Standing) Harm() int {
	return s.overall.Count(LevelNoTrust)
}
