package consumerapi

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/dispute"
	"github.com/NTARI-RAND/Cloudy/internal/record"
)

type openDisputeRequest struct {
	Complainant string `json:"complainant"` // hex ed25519 key; signs the opening
	Respondent  string `json:"respondent"`  // hex ed25519 key of the counterparty
	Exchange    string `json:"exchange"`    // hex leaf ID of the disputed sealed dialog
	ReasonHash  string `json:"reason_hash"` // hex SHA-256 of the member-local reason; the text never enters the commons
	Nonce       string `json:"nonce"`       // hex 32-byte client-drawn nonce
	OpenedAt    string `json:"opened_at"`
	Signature   string `json:"signature"` // hex ed25519 by the complainant

	// Filing is the complainant-signed FilingCommitment over the claim this
	// opening will create: the structural fact lodged at the intake witness
	// BEFORE the operator acts. Its fields commit to a hash, a type, a
	// timestamp, and an exchange reference — never narrative or identity.
	Filing struct {
		TypeHash  string `json:"type_hash"` // hex digest of the dispute-type label
		At        string `json:"at"`
		Signature string `json:"signature"` // hex ed25519 by the complainant over the commitment
	} `json:"filing"`
}

type filingReceiptView struct {
	Witness    string `json:"witness"`
	ReceivedAt string `json:"received_at"`
	Signature  string `json:"signature"`
	// Independent is false whenever the intake witness is the operator —
	// this process's permanent condition until real independent intake
	// witnesses exist. False here means: the operator was NOT absent from
	// this claim's birth, and the receipt proves intake ordering only
	// against the operator's own honesty. Label, not decoration.
	Independent bool `json:"independent"`
}

// handleOpenDispute admits one complainant-signed Opening. The Registry is
// the only admission path and re-verifies the signature, the anchor (the
// named exchange is a sealed dialog between exactly these two members), and
// the one-live-case rule. A dismissal, when adjudication exists, will be an
// annotation — never an erasure; the case index is append-only underneath.
//
// Honest scope note, labeled the stand-in it is: this process holds no
// adjudicator key, so no ruling can be produced here — filed cases stay open
// (visible, with their dwell readable) until they are withdrawn. A real
// adjudication surface arrives with a staff panel, and its lifecycle
// witnessing (file → adjudicate → resolve → seal, filing at an INDEPENDENT
// witness upstream of this operator) is Phase-3 record-federation work; this
// endpoint is the operator-local half, not a substitute for it.
func (s *Server) handleOpenDispute(w http.ResponseWriter, r *http.Request) {
	var req openDisputeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	complainant, ok := decodeKey(req.Complainant)
	if !ok {
		writeErr(w, http.StatusBadRequest, "complainant must be a 32-byte hex ed25519 key")
		return
	}
	respondent, ok := decodeKey(req.Respondent)
	if !ok {
		writeErr(w, http.StatusBadRequest, "respondent must be a 32-byte hex ed25519 key")
		return
	}
	exchange, ok := decodeHex32(req.Exchange)
	if !ok {
		writeErr(w, http.StatusBadRequest, "exchange must be a 32-byte hex leaf ID")
		return
	}
	reasonHash, ok := decodeHex32(req.ReasonHash)
	if !ok {
		writeErr(w, http.StatusBadRequest, "reason_hash must be a 32-byte hex digest")
		return
	}
	nonce, ok := decodeHex32(req.Nonce)
	if !ok {
		writeErr(w, http.StatusBadRequest, "nonce must be 32 hex bytes")
		return
	}
	openedAt, ok := parseUTC(req.OpenedAt)
	if !ok {
		writeErr(w, http.StatusBadRequest, "opened_at must be RFC3339")
		return
	}
	sig, ok := decodeSig(req.Signature)
	if !ok {
		writeErr(w, http.StatusBadRequest, "signature must be a 64-byte hex signature")
		return
	}
	typeHash, ok := decodeHex32(req.Filing.TypeHash)
	if !ok {
		writeErr(w, http.StatusBadRequest, "filing.type_hash must be a 32-byte hex digest")
		return
	}
	filedAt, ok := parseUTC(req.Filing.At)
	if !ok {
		writeErr(w, http.StatusBadRequest, "filing.at must be RFC3339")
		return
	}
	filingSig, ok := decodeSig(req.Filing.Signature)
	if !ok {
		writeErr(w, http.StatusBadRequest, "filing.signature must be a 64-byte hex signature")
		return
	}

	o := dispute.Opening{
		Platform:    s.platform,
		Complainant: complainant,
		Respondent:  respondent,
		Exchange:    dispute.ExchangeRef(exchange),
		ReasonHash:  reasonHash,
		Nonce:       nonce,
		OpenedAt:    openedAt,
		Signature:   sig,
	}
	claimID := o.ID()

	// Intake FIRST: the filing commitment is acknowledged before the
	// operator's registry acts on the opening — the Part-IV ordering, kept
	// even while both roles run in one process.
	commitment := record.FilingCommitment{
		Claim:     record.Hash(claimID),
		Exchange:  record.Hash(exchange),
		TypeHash:  record.Hash(typeHash),
		At:        filedAt,
		Filer:     complainant,
		Signature: filingSig,
	}
	receipt, err := s.intake.Accept(commitment, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "filing commitment refused: "+err.Error())
		return
	}

	s.mu.Lock()
	id, err := s.registry.Open(o)
	if err == nil {
		artifact := sha256.Sum256(o.CanonicalBytes())
		_, err = s.lifeLog.Append(record.Transition{
			Log:      s.lifeID,
			Claim:    record.Hash(id),
			Kind:     record.KindFiled,
			Artifact: record.Hash(artifact),
			Exchange: record.Hash(exchange),
			At:       time.Now().UTC(),
		})
	}
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dispute_id": hx(id[:]),
		"filing_receipt": filingReceiptView{
			Witness:     hx(receipt.Witness),
			ReceivedAt:  receipt.ReceivedAt.UTC().Format(time.RFC3339Nano),
			Signature:   hx(receipt.Signature),
			Independent: receipt.IndependentOf(s.operatorPub),
		},
	})
}

type disputeView struct {
	DisputeID   string `json:"dispute_id"`
	State       string `json:"state"` // open | resolved | withdrawn
	Complainant string `json:"complainant"`
	Respondent  string `json:"respondent"`
	Exchange    string `json:"exchange"`
}

// handleGetDispute serves one case's read model, folded from the ordered
// artifacts — never a stored scalar. Public read: a case is keys, hashes, and
// state; the grievance narrative lives member-local behind ReasonHash.
func (s *Server) handleGetDispute(w http.ResponseWriter, r *http.Request) {
	id, ok := decodeHex32(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "id must be a 32-byte hex dispute ID")
		return
	}
	s.mu.Lock()
	c, err := s.registry.Case(dispute.DisputeID(id))
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusNotFound, "no case with this dispute ID")
		return
	}
	exchange := c.Exchange()
	writeJSON(w, http.StatusOK, disputeView{
		DisputeID:   r.PathValue("id"),
		State:       c.State().String(),
		Complainant: hx(c.Complainant()),
		Respondent:  hx(c.Respondent()),
		Exchange:    hx(exchange[:]),
	})
}

type withdrawRequest struct {
	WithdrawnAt string `json:"withdrawn_at"`
	Signature   string `json:"signature"` // hex ed25519 by the complainant over the withdrawal's canonical bytes
}

// handleWithdrawDispute admits the complainant's signed retraction of their
// own open case. The registry resolves the complainant's key from the stored
// opening — only the member who opened a case can withdraw it, and only while
// it is open.
func (s *Server) handleWithdrawDispute(w http.ResponseWriter, r *http.Request) {
	id, ok := decodeHex32(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "id must be a 32-byte hex dispute ID")
		return
	}
	var req withdrawRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	withdrawnAt, ok := parseUTC(req.WithdrawnAt)
	if !ok {
		writeErr(w, http.StatusBadRequest, "withdrawn_at must be RFC3339")
		return
	}
	sig, ok := decodeSig(req.Signature)
	if !ok {
		writeErr(w, http.StatusBadRequest, "signature must be a 64-byte hex signature")
		return
	}
	wd := dispute.Withdrawal{
		Platform:    s.platform,
		Dispute:     dispute.DisputeID(id),
		WithdrawnAt: withdrawnAt,
		Signature:   sig,
	}
	s.mu.Lock()
	err := s.registry.Withdraw(wd)
	if err == nil {
		var c dispute.Case
		c, cerr := s.registry.Case(dispute.DisputeID(id))
		if cerr == nil {
			exchange := c.Exchange()
			artifact := sha256.Sum256(wd.CanonicalBytes())
			_, err = s.lifeLog.Append(record.Transition{
				Log:      s.lifeID,
				Claim:    record.Hash(id),
				Kind:     record.KindResolved,
				Artifact: record.Hash(artifact),
				Exchange: record.Hash(exchange),
				At:       time.Now().UTC(),
			})
		}
	}
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "withdrawn"})
}
