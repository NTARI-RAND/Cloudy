// Package coord is Cloudy's client to a sohocloud coordinator. It is a thin
// wrapper over the protocol's reference HTTP+JSON transport: it constructs the
// client and exposes the coordination surface Cloudy uses. It adds no policy of
// its own — matching, fee terms, and node identity binding all live on the
// coordinator side (SoHoLINK), per the protocol's design.
package coord

import (
	"net/http"
	"time"

	"github.com/NTARI-RAND/sohocloud-protocol/coordinator"
	"github.com/NTARI-RAND/sohocloud-protocol/transport/httpjson"
)

// Client is Cloudy's handle to a coordinator. It embeds the protocol's
// coordinator.Coordinator, so callers use the protocol's own operation set
// (SubmitListing, Heartbeat, PollJobs, Decline, ReportJob, Fees) directly — the
// wrapper deliberately re-models nothing.
type Client struct {
	coordinator.Coordinator
}

// compile-time proof that Cloudy's client satisfies the protocol interface.
var _ coordinator.Coordinator = (*Client)(nil)

// Dial returns a coord.Client talking to the coordinator at baseURL over the
// reference HTTP+JSON transport.
func Dial(baseURL string) *Client {
	return &Client{
		Coordinator: &httpjson.Client{
			BaseURL: baseURL,
			HTTP:    &http.Client{Timeout: 30 * time.Second},
		},
	}
}

// DialAsOperator returns a client that authenticates every request as an
// operator: decorate mutates each outgoing request, typically setting
// opcred.OperatorHeaderName to a freshly signed+encoded operator transmission
// (the coordinator's /v0 operator-auth seam). The credential wiring lives at
// the caller, so this package stays free of the opcred/protocol operator
// packages and models no policy.
func DialAsOperator(baseURL string, decorate func(*http.Request) error) *Client {
	return &Client{
		Coordinator: &httpjson.Client{
			BaseURL: baseURL,
			HTTP: &http.Client{
				Timeout:   30 * time.Second,
				Transport: &operatorRoundTripper{base: http.DefaultTransport, decorate: decorate},
			},
		},
	}
}

// operatorRoundTripper attaches per-request operator authentication before
// delegating to the base transport. It clones the request (a RoundTripper must
// not mutate its argument) and is fail-closed: if decoration fails the request
// is never sent, so a request can never go out unauthenticated.
type operatorRoundTripper struct {
	base     http.RoundTripper
	decorate func(*http.Request) error
}

func (t *operatorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	if err := t.decorate(r2); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r2)
}
