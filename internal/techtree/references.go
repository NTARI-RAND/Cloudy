package techtree

import "errors"

// ErrReferencePage reports an invalid append cursor, kind, or page size.
var ErrReferencePage = errors.New("techtree: invalid reference cursor, kind, or limit")

// References returns matching accepted edges in append order, with defensive
// copies. Cursor is an absolute log position (claims occupy positions too).
// Next is the first unreturned match's position, or -1 when exhausted. Appends
// cannot shift positions; the caller serializes tree access as for Log.
func (t *Tree) References(id ClaimID, inbound bool, kind RefKind, cursor, limit int) (refs []Reference, next int, err error) {
	if cursor < 0 || cursor > len(t.log) || limit < 1 || limit > 100 {
		return nil, -1, ErrReferencePage
	}
	if kind != "" && !validRefKind(kind) {
		return nil, -1, ErrReferencePage
	}
	if _, ok := t.claims[id]; !ok {
		return nil, -1, ErrUnknownClaim
	}
	refs = make([]Reference, 0, limit)
	for pos := cursor; pos < len(t.log); pos++ {
		ref := t.log[pos].Reference
		if !matchesReference(ref, id, inbound, kind) {
			continue
		}
		if len(refs) == limit {
			return refs, pos, nil
		}
		refs = append(refs, cloneRef(*ref))
	}
	return refs, -1, nil
}

func matchesReference(ref *Reference, id ClaimID, inbound bool, kind RefKind) bool {
	if ref == nil || (kind != "" && ref.Kind != kind) {
		return false
	}
	if inbound {
		return ref.To == id
	}
	return ref.From == id
}
