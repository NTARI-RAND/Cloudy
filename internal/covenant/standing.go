package covenant

// Standing is the LBTAS read view of one member's reputation, typed by
// relation: for each relation, per-category distributions, the pooled
// distribution within that relation, and the harm count. It is built only by
// Book.Standing; its state is unexported, so it cannot be constructed with
// fabricated counts or serialized through this package's types. Deliberately
// absent, like everywhere else in the package: any mean, average, or scalar
// summary of level VALUES; any comparison or ordering between members; and —
// new with typed relations — ANY POOL ACROSS RELATIONS, which would be the
// forbidden average committed across relations instead of across ratings.
type Standing struct {
	perRelation map[Relation]RelationStanding
}

// Relation returns the standing under one typed relation. A relation with no
// assessments yields an empty RelationStanding with Total zero, not an error.
func (s Standing) Relation(r Relation) RelationStanding {
	return s.perRelation[r]
}

// RelationStanding is one relation's slice of a member's standing:
// per-category distributions and the pooled distribution within this one
// relation only.
type RelationStanding struct {
	byCategory map[string]Distribution
	overall    Distribution
}

// Category returns the distribution of admitted assessments about the
// subject under the named category, within this relation. A category with no
// assessments — or a name outside the vocabulary — yields an empty
// Distribution with Total zero, not an error.
func (rs RelationStanding) Category(name string) Distribution {
	return rs.byCategory[name]
}

// Overall returns the pooled distribution across all categories WITHIN THIS
// RELATION: the same verdicts as the per-category views, counted once each,
// in one histogram. It never pools across relations.
func (rs RelationStanding) Overall() Distribution {
	return rs.overall
}

// Total returns the number of admitted assessments in this relation across
// all categories — the distribution's size. Per LBTAS this is itself a
// signal (transaction volume, and a proxy for time in service), never a
// denominator for a mean.
func (rs RelationStanding) Total() int {
	return rs.overall.Total()
}

// Harm returns the count of No Trust (-1) verdicts in this relation. This is
// a per-level count surfaced by name — the never-diluted signal LBTAS
// mandates — NOT a collapse of the distribution. Readers MUST keep relation
// context when acting on it: a No Trust under verdict-satisfaction is a
// losing party's displeasure, not operator misconduct.
func (rs RelationStanding) Harm() int {
	return rs.overall.Count(LevelNoTrust)
}
