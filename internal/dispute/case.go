package dispute

import "crypto/ed25519"

// State is a case's position in the dispute state machine. The zero value is
// invalid (no case has been opened).
type State uint8

const (
	StateOpen      State = iota + 1 // opened, awaiting a ruling or withdrawal
	StateResolved                   // a valid ruling was admitted (terminal)
	StateWithdrawn                  // the complainant withdrew (terminal)
)

// String renders the state for diagnostics.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateResolved:
		return "resolved"
	case StateWithdrawn:
		return "withdrawn"
	}
	return "invalid"
}

// Case is the read model of one dispute, folded from the ordered artifacts in
// the Store — never from a stored scalar (the same replay discipline as
// record.OpenLog and economy.Open). Its state is unexported, so it cannot be
// constructed with fabricated contents or serialized through this package's
// types.
type Case struct {
	id          DisputeID
	exchange    ExchangeRef
	complainant ed25519.PublicKey
	respondent  ed25519.PublicKey
	state       State
	finding     Finding
	remedy      Remedy
}

// ID returns the case identity (its Opening's ID()).
func (c Case) ID() DisputeID { return c.id }

// Exchange returns the disputed exchange reference.
func (c Case) Exchange() ExchangeRef { return c.exchange }

// Complainant returns a fresh copy of the complainant's key.
func (c Case) Complainant() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), c.complainant...)
}

// Respondent returns a fresh copy of the respondent's key.
func (c Case) Respondent() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), c.respondent...)
}

// State returns the case's current state.
func (c Case) State() State { return c.state }

// Finding returns the adjudicated finding; ok is true only when the case is
// resolved.
func (c Case) Finding() (Finding, bool) {
	if c.state != StateResolved {
		return 0, false
	}
	return c.finding, true
}

// Remedy returns a read-only deep copy of the adjudicated remedy; ok is true
// only when the case is resolved.
func (c Case) Remedy() (Remedy, bool) {
	if c.state != StateResolved {
		return Remedy{}, false
	}
	return c.remedy.clone(), true
}
