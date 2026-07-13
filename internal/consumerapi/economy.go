package consumerapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/economy"
)

type policyResponse struct {
	Mode     string `json:"mode"`      // "escrow" or "credit" — the one governed switch
	DebitCap uint64 `json:"debit_cap"` // uniform issuance limit; no account gets a deeper well
}

// handleCreditPolicy serves the ledger's governed policy. In escrow mode the
// API says so plainly — the fee-declaration pattern applied to the credit
// switch: a member reads the rule that governs them at the point of use.
func (s *Server) handleCreditPolicy(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	pol := s.ledger.Policy()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, policyResponse{Mode: string(pol.Mode), DebitCap: uint64(pol.DebitCap)})
}

type balanceResponse struct {
	AccountID string `json:"account_id"`
	Balance   int64  `json:"balance"`
}

// handleBalance serves one account's balance, derived by folding the sealed
// ledger — never a stored scalar. Public read: balances are keyed by opaque
// derived AccountIDs and carry no PII.
func (s *Server) handleBalance(w http.ResponseWriter, r *http.Request) {
	id, ok := decodeHex32(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "id must be a 32-byte hex account ID")
		return
	}
	s.mu.Lock()
	bal := s.ledger.Balance(economy.AccountID(id))
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, balanceResponse{AccountID: r.PathValue("id"), Balance: int64(bal)})
}

type spendView struct {
	Position     int    `json:"position"` // append position in the ledger
	From         string `json:"from"`
	To           string `json:"to"`
	Amount       uint64 `json:"amount"`
	ExchangeHash string `json:"exchange_hash"` // leaf ID of the sealed dialog this spend commits to
	IssuedAt     string `json:"issued_at"`
	Nonce        uint64 `json:"nonce"`
}

type historyResponse struct {
	AccountID string      `json:"account_id"`
	Spends    []spendView `json:"spends"`
}

// handleHistory serves the spends touching one account, in ledger order.
// Balances and history answer to the same fold, so what this returns is by
// construction consistent with handleBalance — one deterministic function of
// the sealed record, per the economy invariant.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := decodeHex32(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "id must be a 32-byte hex account ID")
		return
	}
	acct := economy.AccountID(id)
	s.mu.Lock()
	records, err := s.ecoStore.All()
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "reading ledger")
		return
	}
	out := historyResponse{AccountID: r.PathValue("id"), Spends: []spendView{}}
	for i, rec := range records {
		sp, isSpend := rec.(economy.Spend)
		if !isSpend || (sp.From != acct && sp.To != acct) {
			continue
		}
		out.Spends = append(out.Spends, spendView{
			Position:     i,
			From:         hx(sp.From[:]),
			To:           hx(sp.To[:]),
			Amount:       uint64(sp.Amount),
			ExchangeHash: hx(sp.ExchangeHash[:]),
			IssuedAt:     sp.IssuedAt.UTC().Format(time.RFC3339Nano),
			Nonce:        sp.Nonce,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type spendRequest struct {
	From         string `json:"from"` // hex account ID of the payer; its member key signs
	To           string `json:"to"`
	Amount       uint64 `json:"amount"`
	ExchangeHash string `json:"exchange_hash"` // hex leaf ID of the sealed dialog
	IssuedAt     string `json:"issued_at"`
	Nonce        uint64 `json:"nonce"`     // strictly monotonic per payer account
	Signature    string `json:"signature"` // hex ed25519 by the payer over the spend's canonical bytes
}

// handlePostSpend accepts one payer-signed spend. The server signs nothing:
// the spend arrives sealed by the payer's own key (client-side, like every
// member artifact here) and the ledger re-verifies signature, nonce, parties,
// and the debit cap on admission.
//
// While the governed policy is escrow mode, the ledger refuses every spend
// with ErrCreditDisabled and this endpoint reports that honestly as 409 —
// the escrow→credit transition is a governed PolicyChange (bylaws §5.7:
// Board approval, membership notice, completed regulatory review), never an
// API affordance. There is deliberately no endpoint that could flip it.
func (s *Server) handlePostSpend(w http.ResponseWriter, r *http.Request) {
	var req spendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	from, ok := decodeHex32(req.From)
	if !ok {
		writeErr(w, http.StatusBadRequest, "from must be a 32-byte hex account ID")
		return
	}
	to, ok := decodeHex32(req.To)
	if !ok {
		writeErr(w, http.StatusBadRequest, "to must be a 32-byte hex account ID")
		return
	}
	exchange, ok := decodeHex32(req.ExchangeHash)
	if !ok {
		writeErr(w, http.StatusBadRequest, "exchange_hash must be a 32-byte hex leaf ID")
		return
	}
	issuedAt, ok := parseUTC(req.IssuedAt)
	if !ok {
		writeErr(w, http.StatusBadRequest, "issued_at must be RFC3339")
		return
	}
	sig, ok := decodeSig(req.Signature)
	if !ok {
		writeErr(w, http.StatusBadRequest, "signature must be a 64-byte hex signature")
		return
	}
	sp := economy.Spend{
		Platform:     s.platform,
		From:         economy.AccountID(from),
		To:           economy.AccountID(to),
		Amount:       economy.Amount(req.Amount),
		ExchangeHash: exchange,
		IssuedAt:     issuedAt,
		Nonce:        req.Nonce,
		Signature:    sig,
	}
	s.mu.Lock()
	err := s.ledger.Post(sp)
	s.mu.Unlock()
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"status": "posted"})
	case errors.Is(err, economy.ErrCreditDisabled):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}
