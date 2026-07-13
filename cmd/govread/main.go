// Command govread is the governance read's first rendering: it reads one
// operator's claim-lifecycle surface (the consumer API) and prints the
// STRUCTURE a governance reader may consider — dwell shape, state counts,
// transition history — with the evidence label carried on every line.
//
// It is a legibility tool that confers no authority. It computes no score,
// ranks nothing, decides nothing, and prints facts a human contests: the
// scan flags, adjudication decides, the operator answers (architecture,
// Part IV–V). Until the log's checkpoints carry two or more independent
// witness countersignatures, everything below is SELF-ATTESTED BY THE
// OPERATOR and the output says so on every run — dispositions made on such
// evidence must name it (bylaws §2.7 discipline).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"
)

type checkpointMsg struct {
	Size    uint64 `json:"size"`
	StandIn bool   `json:"stand_in"`
}

type transitionView struct {
	Kind string `json:"kind"`
	At   string `json:"at"`
}

type claimView struct {
	ClaimID     string           `json:"claim_id"`
	State       string           `json:"state"`
	FiledAt     string           `json:"filed_at"`
	Transitions []transitionView `json:"transitions"`
}

func fetch(base, path string, v any) error {
	resp, err := http.Get(base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func main() {
	base := flag.String("operator", "http://localhost:8088", "operator consumer-API base URL")
	claims := flag.String("claims", "", "comma-separated claim IDs to read (the lifecycle surface is per-claim; discovery of all claims arrives with the register read)")
	flag.Parse()

	var cp checkpointMsg
	if err := fetch(*base, "/api/v1/lifecycle/checkpoints", &cp); err != nil {
		fmt.Fprintf(os.Stderr, "govread: reading lifecycle checkpoint: %v\n", err)
		os.Exit(1)
	}

	label := "FEDERATED (>=2 independent witnesses)"
	if cp.StandIn {
		label = "SELF-ATTESTED (single-witness stand-in: the operator vouches for itself; treat every figure below accordingly)"
	}
	fmt.Printf("govread — operator lifecycle read at %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("evidence: %s\n", label)
	fmt.Printf("lifecycle log size: %d transition(s)\n\n", cp.Size)

	if *claims == "" {
		fmt.Println("no claim IDs given (-claims); nothing further to read.")
		fmt.Println("what a reader MAY infer from this surface: dwell SHAPES, dismissal")
		fmt.Println("patterns, and state counts — never a verdict. what a reader may NOT")
		fmt.Println("do: average anything, rank anyone, or treat a flag as a finding.")
		return
	}

	var dwells []time.Duration
	states := map[string]int{}
	start := 0
	for _, id := range splitComma(*claims) {
		var c claimView
		if err := fetch(*base, "/api/v1/lifecycle/claims/"+id, &c); err != nil {
			fmt.Printf("claim %s: unreadable (%v)\n", id, err)
			continue
		}
		states[c.State]++
		filed, err := time.Parse(time.RFC3339Nano, c.FiledAt)
		if err == nil && (c.State == "filed" || c.State == "adjudicated") {
			dwells = append(dwells, time.Since(filed))
		}
		fmt.Printf("claim %s: state=%s filed=%s transitions=%d\n", short(id), c.State, c.FiledAt, len(c.Transitions))
		start++
	}

	fmt.Printf("\nstate counts: %v\n", states)
	if len(dwells) > 0 {
		sort.Slice(dwells, func(i, j int) bool { return dwells[i] < dwells[j] })
		fmt.Println("dwell shape (unresolved claims, age since filing — the SHAPE is the")
		fmt.Println("signal; a count or an open/closed ratio inverts against busy honest")
		fmt.Println("operators and is deliberately not printed):")
		for _, d := range dwells {
			fmt.Printf("  %s\n", d.Truncate(time.Second))
		}
	}
	fmt.Println("\nThis output is an input to contestation, never a verdict: a flag is")
	fmt.Println("raised to a venue where the operator answers; disposition belongs to")
	fmt.Println("the contested federation, not to this tool or its operator.")
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}
