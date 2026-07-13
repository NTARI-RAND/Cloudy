// Command witness-relay runs the witness relay: it caches operator
// checkpoints, collects witness countersignatures, serves assembled
// bundles, and fans filing commitments out to witness intakes. It decides
// nothing, ranks nothing, and gates nothing; everything it does remains
// possible without it (operators serve their own checkpoints; filers can
// hit intakes directly). Kill it and the record's guarantees are unchanged
// — only the convenience is gone. Its cache is in-memory and
// reconstructible by design.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/NTARI-RAND/Cloudy/internal/relay"
)

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	intakes := flag.String("intakes", "", "comma-separated witness intake base URLs for filing fan-out")
	flag.Parse()

	var urls []string
	if *intakes != "" {
		urls = strings.Split(*intakes, ",")
	}
	rl := relay.New(urls)
	log.Printf("witness-relay: listening on %s; %d filing intakes configured; caches and serves, never adjudicates", *addr, len(urls))
	if err := http.ListenAndServe(*addr, rl.Handler()); err != nil {
		log.Fatalf("witness-relay: %v", err)
	}
}
