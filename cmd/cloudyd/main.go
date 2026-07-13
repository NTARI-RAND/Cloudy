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
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/NTARI-RAND/Cloudy/internal/consumerapi"
)

func main() {
	addr := flag.String("addr", ":8088", "listen address for the consumer JSON API")
	platform := flag.String("platform", "cloudy", "platform identity (scopes member ids and every artifact)")
	flag.Parse()

	srv, err := consumerapi.NewServer(*platform)
	if err != nil {
		log.Fatalf("cloudyd: constructing server: %v", err)
	}

	log.Printf("cloudyd: consumer JSON API (slices 1+2: members, techtree, market, drops, covenant, credit, disputes) listening on %s for platform %q; in-memory stores, member keys never touch this process (client-signed artifacts only); credit policy is escrow (spends 409 until the governed switch); checkpoints carry the single-witness stand-in label", *addr, *platform)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatalf("cloudyd: server exited: %v", err)
	}
}
