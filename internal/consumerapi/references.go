package consumerapi

import (
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/NTARI-RAND/Cloudy/internal/techtree"
)

// referenceExport contains structural fields only. Decimal-string nanoseconds
// preserve every signed timestamp bit in clients whose JSON numbers are doubles.
type referenceExport struct {
	ReferenceID  string `json:"reference_id"`
	Platform     string `json:"platform"`
	Asserter     string `json:"asserter"`
	Kind         string `json:"kind"`
	From         string `json:"from"`
	To           string `json:"to"`
	Nonce        string `json:"nonce"`
	AssertedAtNs string `json:"asserted_at_ns"`
	Signature    string `json:"signature"`
}

type referenceQuery struct {
	inbound       bool
	kind          techtree.RefKind
	cursor, limit int
}

func parseReferenceQuery(q url.Values) (referenceQuery, error) {
	result := referenceQuery{limit: 50}
	for _, name := range []string{"direction", "kind", "cursor", "limit"} {
		if len(q[name]) > 1 {
			return result, errors.New("reference query parameters must not be repeated")
		}
	}
	switch q.Get("direction") {
	case "inbound":
		result.inbound = true
	case "outbound":
	default:
		return result, errors.New("direction must be inbound or outbound")
	}
	result.kind = techtree.RefKind(q.Get("kind"))
	if _, present := q["kind"]; present && result.kind == "" {
		return result, errors.New("kind must name an existing reference kind")
	}
	var err error
	result.cursor, err = parsePageNumber(q.Get("cursor"), 0)
	if err != nil {
		return result, err
	}
	if _, present := q["limit"]; present {
		result.limit, err = parsePageNumber(q.Get("limit"), -1)
	}
	return result, err
}

func parsePageNumber(raw string, fallback int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, errors.New("cursor and limit must be unsigned decimal integers")
		}
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("cursor or limit exceeds integer range")
	}
	return n, nil
}

func (s *Server) handleGetReferences(w http.ResponseWriter, r *http.Request) {
	raw, ok := decodeHex32(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "claim id must be 32-byte hex")
		return
	}
	query, err := parseReferenceQuery(r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	refs, next, err := s.tree.References(techtree.ClaimID(raw), query.inbound, query.kind, query.cursor, query.limit)
	s.mu.Unlock()
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, techtree.ErrUnknownClaim) {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	out := make([]referenceExport, 0, len(refs))
	for _, ref := range refs {
		out = append(out, exportReference(ref))
	}
	cursor := ""
	if next >= 0 {
		cursor = strconv.Itoa(next)
	}
	writeJSON(w, http.StatusOK, struct {
		References []referenceExport `json:"references"`
		NextCursor string            `json:"next_cursor"`
	}{out, cursor})
}

func exportReference(ref techtree.Reference) referenceExport {
	id := ref.ID()
	return referenceExport{
		ReferenceID: hex.EncodeToString(id[:]), Platform: ref.Platform, Asserter: hx(ref.Asserter), Kind: string(ref.Kind),
		From: hex.EncodeToString(ref.From[:]), To: hex.EncodeToString(ref.To[:]), Nonce: hex.EncodeToString(ref.Nonce[:]),
		AssertedAtNs: strconv.FormatInt(ref.AssertedAt.UnixNano(), 10), Signature: hx(ref.Signature),
	}
}
