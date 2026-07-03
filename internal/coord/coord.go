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
