// Package witnesskit is what a MEMBER runs to be a witness — the
// membership-as-witnessing seam (open problem 8's most architecture-shaped
// lever): distribute witness capacity across the membership so a node can be
// governed-honest without being witness-rich. A worker holds one witness
// key, polls a relay (or an operator directly — the relay is convenience,
// not dependency), refuses rollbacks and forks by construction
// (record.Witness's memory), countersigns what extends honestly, and posts
// the countersignature back. It also hosts the filing intake: the one
// witness write.
//
// Running one is deliberately boring: any member, any machine, one key.
// Federation is the plural of this package.
package witnesskit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/record"
	"github.com/NTARI-RAND/Cloudy/internal/relay"
)

// EncodeCheckpoint builds the relay wire form of a checkpoint.
func EncodeCheckpoint(cp record.Checkpoint, operator ed25519.PublicKey, kind string, from uint64, proof []record.Hash) relay.CheckpointMsg {
	msg := relay.CheckpointMsg{
		Log:             hex.EncodeToString(cp.Log[:]),
		Size:            cp.Size,
		Head:            hex.EncodeToString(cp.Head[:]),
		IssuedAt:        cp.IssuedAt.UTC().Format(time.RFC3339Nano),
		Signature:       hex.EncodeToString(cp.Signature),
		Operator:        hex.EncodeToString(operator),
		Kind:            kind,
		ConsistencyFrom: from,
	}
	msg.ConsistencyProof = make([]string, len(proof))
	for i, h := range proof {
		msg.ConsistencyProof[i] = hex.EncodeToString(h[:])
	}
	return msg
}

func decodeHash(s string) (record.Hash, error) {
	var h record.Hash
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return h, errors.New("witnesskit: not a 32-byte hex hash")
	}
	copy(h[:], raw)
	return h, nil
}

// DecodeCheckpoint parses the wire form, derives the expected log identity
// from the operator key and kind, and REFUSES a message whose log id does
// not match the derivation — a witness never takes the relay's word for
// which log a checkpoint belongs to.
func DecodeCheckpoint(msg relay.CheckpointMsg) (cp record.Checkpoint, operator ed25519.PublicKey, wantLog record.Hash, proof []record.Hash, err error) {
	logID, err := decodeHash(msg.Log)
	if err != nil {
		return cp, nil, wantLog, nil, err
	}
	head, err := decodeHash(msg.Head)
	if err != nil {
		return cp, nil, wantLog, nil, err
	}
	opRaw, err := hex.DecodeString(msg.Operator)
	if err != nil || len(opRaw) != ed25519.PublicKeySize {
		return cp, nil, wantLog, nil, errors.New("witnesskit: malformed operator key")
	}
	operator = ed25519.PublicKey(opRaw)
	switch msg.Kind {
	case "dialog":
		wantLog = record.LogID(operator)
	case "lifecycle":
		wantLog = record.LifecycleLogID(operator)
	default:
		return cp, nil, wantLog, nil, fmt.Errorf("witnesskit: unknown log kind %q", msg.Kind)
	}
	if logID != wantLog {
		return cp, nil, wantLog, nil, errors.New("witnesskit: log id does not derive from operator key and kind")
	}
	sig, err := hex.DecodeString(msg.Signature)
	if err != nil {
		return cp, nil, wantLog, nil, errors.New("witnesskit: malformed signature")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, msg.IssuedAt)
	if err != nil {
		return cp, nil, wantLog, nil, errors.New("witnesskit: malformed issued_at")
	}
	cp = record.Checkpoint{Log: logID, Size: msg.Size, Head: head, IssuedAt: issuedAt.UTC(), Signature: sig}
	proof = make([]record.Hash, 0, len(msg.ConsistencyProof))
	for _, s := range msg.ConsistencyProof {
		h, err := decodeHash(s)
		if err != nil {
			return cp, nil, wantLog, nil, err
		}
		proof = append(proof, h)
	}
	return cp, operator, wantLog, proof, nil
}

// Worker is one member witness: a key, a rollback memory, and a relay to
// poll. Its state is process-volatile (the named amnesia residual: a
// restarted witness reverts to trust-on-first-checkpoint); run it long-lived.
type Worker struct {
	witness *record.Witness
	intake  *record.FilingIntake
	pub     ed25519.PublicKey
	relay   string
	client  *http.Client
}

// NewWorker returns a worker holding priv, polling relayURL.
func NewWorker(priv ed25519.PrivateKey, relayURL string) *Worker {
	w := &Worker{
		witness: record.NewWitness(priv),
		intake:  record.NewFilingIntake(priv),
		relay:   relayURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
	if len(priv) == ed25519.PrivateKeySize {
		w.pub = priv.Public().(ed25519.PublicKey)
	}
	return w
}

// Key returns the worker's witness public key.
func (w *Worker) Key() ed25519.PublicKey { return w.pub }

// RunOnce polls every log the relay knows, countersigns each checkpoint
// that verifies and consistently extends what this witness last cosigned,
// and posts the countersignatures back. It returns how many logs it
// countersigned. Failures on one log never block another.
func (w *Worker) RunOnce() (int, error) {
	resp, err := w.client.Get(w.relay + "/v1/logs")
	if err != nil {
		return 0, err
	}
	var logs struct {
		Logs []string `json:"logs"`
	}
	err = json.NewDecoder(resp.Body).Decode(&logs)
	resp.Body.Close()
	if err != nil {
		return 0, err
	}
	signed := 0
	for _, logID := range logs.Logs {
		if w.countersignLog(logID) == nil {
			signed++
		}
	}
	return signed, nil
}

func (w *Worker) countersignLog(logID string) error {
	resp, err := w.client.Get(w.relay + "/v1/logs/" + logID + "/checkpoints/latest")
	if err != nil {
		return err
	}
	var bundle relay.BundleMsg
	err = json.NewDecoder(resp.Body).Decode(&bundle)
	resp.Body.Close()
	if err != nil {
		return err
	}
	cp, operator, wantLog, proof, err := DecodeCheckpoint(bundle.Checkpoint)
	if err != nil {
		return err
	}
	cs, err := w.witness.CountersignAs(cp, operator, wantLog, proof)
	if err != nil {
		return err
	}
	msg := relay.CountersigMsg{
		Log:       logID,
		Size:      cp.Size,
		Witness:   hex.EncodeToString(cs.Witness),
		Signature: hex.EncodeToString(cs.Signature),
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	post, err := w.client.Post(w.relay+"/v1/logs/"+logID+"/countersignatures", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	post.Body.Close()
	if post.StatusCode != http.StatusOK {
		return fmt.Errorf("witnesskit: relay refused countersignature: %d", post.StatusCode)
	}
	return nil
}

// FilingMsg is the wire form of a FilingCommitment.
type FilingMsg struct {
	Claim     string `json:"claim"`
	Exchange  string `json:"exchange"`
	TypeHash  string `json:"type_hash"`
	At        string `json:"at"`
	Filer     string `json:"filer"`
	Signature string `json:"signature"`
}

// ReceiptMsg is the wire form of a FilingReceipt.
type ReceiptMsg struct {
	Claim      string `json:"claim"`
	Witness    string `json:"witness"`
	ReceivedAt string `json:"received_at"`
	Signature  string `json:"signature"`
}

// IntakeHandler mounts the one witness write: POST /v1/filings. Everything
// else about a claim happens elsewhere; this endpoint acknowledges
// existence at an instant and nothing more.
func (w *Worker) IntakeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/filings", func(rw http.ResponseWriter, r *http.Request) {
		var msg FilingMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(rw, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
			return
		}
		claim, err1 := decodeHash(msg.Claim)
		exchange, err2 := decodeHash(msg.Exchange)
		typeHash, err3 := decodeHash(msg.TypeHash)
		filerRaw, err4 := hex.DecodeString(msg.Filer)
		sig, err5 := hex.DecodeString(msg.Signature)
		at, err6 := time.Parse(time.RFC3339Nano, msg.At)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil ||
			len(filerRaw) != ed25519.PublicKeySize {
			http.Error(rw, `{"error":"malformed filing commitment"}`, http.StatusBadRequest)
			return
		}
		f := record.FilingCommitment{
			Claim:     claim,
			Exchange:  exchange,
			TypeHash:  typeHash,
			At:        at.UTC(),
			Filer:     ed25519.PublicKey(filerRaw),
			Signature: sig,
		}
		receipt, err := w.intake.Accept(f, time.Now().UTC())
		if err != nil {
			http.Error(rw, `{"error":"filing refused"}`, http.StatusBadRequest)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(ReceiptMsg{
			Claim:      msg.Claim,
			Witness:    hex.EncodeToString(receipt.Witness),
			ReceivedAt: receipt.ReceivedAt.UTC().Format(time.RFC3339Nano),
			Signature:  hex.EncodeToString(receipt.Signature),
		})
	})
	return mux
}
