package market

// AcceptedRails is the set of settlement rails a listing accepts. It is the
// per-market half of the two-level credit gate: the global economy Mode decides
// whether member credit is POSSIBLE platform-wide (Sybil + regulatory gated),
// and this decides whether a given market OFFERS it. There is one sovereign
// currency — this is acceptance, never a per-market currency or rate.
//
// Fiat and member credit are separate rails: a single transaction settles on
// exactly one, and the two are never convertible. A listing MUST accept at
// least one rail.
type AcceptedRails struct {
	Fiat         bool // traditional settlement (e.g. Stripe); works day one
	MemberCredit bool // Cloudy member-issued credit; only live once economy Mode is ModeCredit
}

// Valid reports whether at least one rail is accepted.
func (r AcceptedRails) Valid() bool {
	return r.Fiat || r.MemberCredit
}

// canonByte encodes the rail set as one deterministic byte for the signing
// payload (bit0 = fiat, bit1 = member_credit), so the accepted rails are inside
// the maker's signature and cannot be altered after listing.
func (r AcceptedRails) canonByte() byte {
	var b byte
	if r.Fiat {
		b |= 1
	}
	if r.MemberCredit {
		b |= 2
	}
	return b
}
