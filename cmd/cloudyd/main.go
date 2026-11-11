// Command cloudyd is Cloudy's member-facing daemon: it serves the consumer
// JSON API (internal/consumerapi) that the React Native app talks to. This is
// the member-facing ingress cmd/cloudy's composition root said did not yet
// exist. Slice 1: onboarding, the Technology Tree, and the hardware Market.
// Slice 2: the four-leaf member economy — Drops (dialog-sealed record with
// honestly stand-in-labeled checkpoints), LBTAS assessments, credit spends
// (409 while the governed policy is escrow), and dispute filing/withdrawal.
//
// Honest about what it is (like cmd/cloudy): in-memory stores, an ephemeral
// platform, no durable persistence and no live coordination loop. Member keys
// never reach this process — every member artifact arrives client-signed and is
// only validated here; the steward and adjudicator private keys are discarded
// at startup, so no escrow->credit PolicyChange and no ruling is signable.
// Durable persistence, witness federation (lifecycle witnessing included),
// and the settlement + contribution slices are the named follow-ups.
//
// With -orchestrator set, cloudyd also relays its members' computers to the
// orchestrator (decision 0001, internal/noderelay): agents call cloudyd's
// /v0 routes, and cloudyd forwards their signed messages under this
// frontend's operator credential, rolling up heartbeats and polls. Enrolled
// nodes come from -nodes (a stand-in for member-driven enrollment).
package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/NTARI-RAND/Cloudy/internal/consumerapi"
)

func main() {
	addr := flag.String("addr", ":8088", "listen address for the consumer JSON API")
	platform := flag.String("platform", "cloudy", "platform identity (scopes member ids and every artifact)")
	var rc relayConfig
	flag.StringVar(&rc.Orchestrator, "orchestrator", "", "orchestrator base URL; when set, relay members' nodes to it (decision 0001)")
	flag.StringVar(&rc.OperatorID, "operator-id", "", "operator id this frontend enrolled under (cloudy-enroll -slug)")
	flag.StringVar(&rc.KeysDir, "operator-keys", "", "directory of the operator's 7 key-seed files (cloudy-enroll -keys)")
	flag.StringVar(&rc.NodesFile, "nodes", "", "file of enrolled nodes: one \"<node-id> <base64 public key>\" per line")
	flag.DurationVar(&rc.Beat, "relay-beat", 0, "forward at most one heartbeat per node per this interval (default 60s)")
	flag.DurationVar(&rc.Poll, "relay-poll", 0, "poll the orchestrator at most once per node per this interval (default 30s)")
	flag.Parse()

	srv, err := consumerapi.NewServer(*platform)
	if err != nil {
		log.Fatalf("cloudyd: constructing server: %v", err)
	}

	log.Printf("cloudyd: consumer JSON API (slices 1+2: members, techtree, market, drops, covenant, credit, disputes) listening on %s for platform %q; in-memory stores, member keys never touch this process (client-signed artifacts only); credit policy is escrow (spends 409 until the governed switch); checkpoints carry the single-witness stand-in label", *addr, *platform)
	handler := srv.Handler()
	if rc.Orchestrator != "" {
		relay, err := newRelay(context.Background(), rc)
		if err != nil {
			log.Fatalf("cloudyd: node relay: %v", err)
		}
		mux := http.NewServeMux()
		mux.Handle("/v0/", relay.Handler())
		mux.Handle("/", handler)
		handler = mux
		log.Printf("cloudyd: relaying members' nodes to %s as operator %q (heartbeats rolled up)", rc.Orchestrator, rc.OperatorID)
	}
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatalf("cloudyd: server exited: %v", err)
	}
}
