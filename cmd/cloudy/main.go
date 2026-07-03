// Command cloudy is the entrypoint for the Cloudy frontend.
//
// This is a skeleton. It wires nothing live: it constructs a coordinator client
// and reports startup. The JFA member economy (credit, covenant, record) is not
// built — see the internal/economy, internal/covenant, and internal/record
// package docs.
package main

import (
	"flag"
	"log"

	"github.com/NTARI-RAND/Cloudy/internal/coord"
)

func main() {
	addr := flag.String("coordinator", "http://localhost:8080", "base URL of the sohocloud coordinator")
	flag.Parse()

	c := coord.Dial(*addr)
	_ = c // constructed and deliberately unused: the skeleton has no live loop

	log.Printf("cloudy: skeleton startup; coordinator client constructed for %s", *addr)
	log.Printf("cloudy: no live coordination loop yet; member economy not built (economy/covenant/record are stubs)")
}
