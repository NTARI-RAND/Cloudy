package covenant

// Distribution is the count of admitted assessments at each of the six LBTAS
// levels, plus the total. Over this finite ordinal domain the histogram IS
// the distribution — lossless, nothing summarized. Deliberately absent: Sum,
// Mean, Score, Median, Percentile, and any comparison or ordering between
// members; those are collapses, and the shape they erase is the signal.
// Its state is unexported, so it cannot be serialized through this package's
// types.
type Distribution struct {
	counts map[Level]int
	total  int
}

// Count returns how many admitted assessments landed at level l (0 for an
// unknown level).
func (d Distribution) Count(l Level) int {
	return d.counts[l]
}

// Total returns the number of assessments in the distribution — its size,
// never a summary of its values. Per LBTAS, the total is itself a signal:
// it carries transaction volume and a proxy for time in service, exactly the
// magnitude a mean would discard. Always read it alongside the per-level
// counts.
func (d Distribution) Total() int {
	return d.total
}
