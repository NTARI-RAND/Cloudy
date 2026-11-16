package coord

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Reverting the protocol pin would silently accept an extra response value.
func TestCoordinatorResponseFraming(t *testing.T) {
	for _, operator := range []bool{false, true} {
		for _, suffix := range []string{" \t\r\n", " {}"} {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := "[]"
				if r.URL.Path == "/v0/fees" {
					body = "{}"
				}
				_, _ = w.Write([]byte(body + suffix))
			}))
			client := Dial(server.URL)
			if operator {
				client = DialAsOperator(server.URL, func(*http.Request) error { return nil })
			}
			_, jobsError := client.PollJobs(context.Background(), "node")
			_, feesError := client.Fees(context.Background())
			server.Close()
			wantError := suffix == " {}"
			if (jobsError != nil) != wantError || (feesError != nil) != wantError {
				t.Fatalf("operator=%v suffix=%q jobs=%v fees=%v", operator, suffix, jobsError, feesError)
			}
		}
	}
}
