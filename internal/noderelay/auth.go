package noderelay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/canon"
	"github.com/NTARI-RAND/sohocloud-protocol/identity"
	"github.com/NTARI-RAND/sohocloud-protocol/transport/httpjson"
)

// NodeAuthHeader carries a node's request signature to its frontend. It is a
// frontend-local credential, not part of the protocol wire: the orchestrator
// never sees it (the relay re-sends each message under the operator's
// credential instead).
const NodeAuthHeader = "X-Cloudy-Node-Auth"

// AuthWindow is how far a request's timestamp may be from the frontend's
// clock. Requests must also carry strictly increasing timestamps per node, so
// a captured header cannot be replayed even inside the window.
const AuthWindow = 2 * time.Minute

const domainRequest = "cloudy/noderelay/request/v0"

const maxBody = 1 << 20

type authWire struct {
	NodeID string `json:"node_id"`
	TS     int64  `json:"ts_unix_nano"`
	Sig    string `json:"sig"`
}

func requestBytes(method, target string, node identity.NodeID, ts int64) []byte {
	return canon.New(domainRequest).String(method).String(target).String(string(node)).Int64(ts).Sum()
}

// NodeAuth returns a request decorator for the agent: it signs the method,
// path and query, node ID and a timestamp with the node's key. Timestamps are
// strictly increasing even if the clock stalls.
func NodeAuth(node identity.NodeID, key ed25519.PrivateKey, now func() time.Time) func(*http.Request) error {
	if now == nil {
		now = time.Now
	}
	var mu sync.Mutex
	var last int64
	return func(r *http.Request) error {
		mu.Lock()
		ts := now().UnixNano()
		if ts <= last {
			ts = last + 1
		}
		last = ts
		mu.Unlock()
		sig := ed25519.Sign(key, requestBytes(r.Method, r.URL.RequestURI(), node, ts))
		raw, err := json.Marshal(authWire{NodeID: string(node), TS: ts, Sig: base64.StdEncoding.EncodeToString(sig)})
		if err != nil {
			return err
		}
		r.Header.Set(NodeAuthHeader, base64.StdEncoding.EncodeToString(raw))
		return nil
	}
}

// signedPOSTs are the node calls whose body names the node (SPEC §6).
var signedPOSTs = map[string]bool{"/v0/listing": true, "/v0/heartbeat": true, "/v0/decline": true, "/v0/report": true}

// Handler serves the relay to nodes over the protocol's reference HTTP+JSON
// transport, behind node request authentication. GET /v0/fees is open, as
// SPEC §6 allows anyone to read fees. Every other call must carry a valid
// NodeAuthHeader from an enrolled node, and the node it signs as must be the
// node the call names (the SPEC §2 binding, applied at the frontend): 401 when
// the credential is missing or invalid, 403 when it names another node.
func (r *Relay) Handler() http.Handler {
	inner := httpjson.Handler(r)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Path == "/v0/fees" {
			inner.ServeHTTP(w, req)
			return
		}
		node, err := r.authenticate(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		named, body, err := namedNode(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if named != "" && named != node {
			http.Error(w, "noderelay: request signed by one node names another", http.StatusForbidden)
			return
		}
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		inner.ServeHTTP(w, req)
	})
}

// authenticate verifies the request's NodeAuthHeader and returns the node it
// was signed by.
func (r *Relay) authenticate(req *http.Request) (identity.NodeID, error) {
	raw := req.Header.Get(NodeAuthHeader)
	if raw == "" {
		return "", errors.New("noderelay: missing " + NodeAuthHeader)
	}
	jb, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", errors.New("noderelay: malformed " + NodeAuthHeader)
	}
	var a authWire
	if err := json.Unmarshal(jb, &a); err != nil || a.NodeID == "" {
		return "", errors.New("noderelay: malformed " + NodeAuthHeader)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil {
		return "", errors.New("noderelay: malformed signature")
	}
	node := identity.NodeID(a.NodeID)
	skew := r.now().Sub(time.Unix(0, a.TS))
	if skew > AuthWindow || skew < -AuthWindow {
		return "", errors.New("noderelay: request timestamp outside the " + AuthWindow.String() + " window")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.node(node)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(st.pub, requestBytes(req.Method, req.URL.RequestURI(), node, a.TS), sig) {
		return "", errors.New("noderelay: request signature does not verify")
	}
	if a.TS <= st.lastAuthTS {
		return "", errors.New("noderelay: replayed request (timestamp " + strconv.FormatInt(a.TS, 10) + " not newer than the last)")
	}
	st.lastAuthTS = a.TS
	return node, nil
}

// namedNode returns the node a call names: the body's NodeID for the signed
// POSTs (with the body buffered so it can be re-read), the node_id query for
// GET /v0/jobs, or "" for anything else.
func namedNode(req *http.Request) (identity.NodeID, []byte, error) {
	switch {
	case req.Method == http.MethodPost && signedPOSTs[req.URL.Path]:
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
		if err != nil {
			return "", nil, err
		}
		if len(body) > maxBody {
			return "", nil, errors.New("noderelay: request body too large")
		}
		var probe struct{ NodeID string }
		if err := json.Unmarshal(body, &probe); err != nil || probe.NodeID == "" {
			return "", nil, errors.New("noderelay: body names no NodeID")
		}
		return identity.NodeID(probe.NodeID), body, nil
	case req.Method == http.MethodGet && req.URL.Path == "/v0/jobs":
		id := req.URL.Query().Get("node_id")
		if id == "" {
			return "", nil, errors.New("noderelay: missing node_id")
		}
		return identity.NodeID(id), nil, nil
	}
	return "", nil, nil
}
