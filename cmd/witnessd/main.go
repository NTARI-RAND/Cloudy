// Command witnessd is a MEMBER's witness daemon — membership-as-witnessing,
// runnable by anyone with a key and a connection: it polls a relay, refuses
// rollbacks and forks by construction, countersigns honest extensions, and
// hosts the filing intake (the one witness write). Two or more of these,
// run by independent members, are what turns every stand-in label in the
// stack into real federation.
//
// Named residual (the amnesia gap, open problem 2): this process's rollback
// memory starts empty, so its first sight of each log is
// trust-on-first-checkpoint. Run it long-lived; durable witness state is a
// deployment concern the record layer names rather than hides.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/witnesskit"
)

func main() {
	relayURL := flag.String("relay", "http://localhost:8090", "witness relay base URL")
	intakeAddr := flag.String("intake", ":8091", "listen address for the filing intake")
	interval := flag.Duration("interval", 30*time.Second, "poll interval")
	seedHex := flag.String("seed", "", "hex ed25519 seed (32 bytes); ephemeral when empty — ephemeral witnesses forget, use a persistent seed in anything but a demo")
	flag.Parse()

	var priv ed25519.PrivateKey
	if *seedHex == "" {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("witnessd: generating key: %v", err)
		}
		priv = p
		log.Printf("witnessd: EPHEMERAL key (amnesia on restart is total); pass -seed for anything beyond a demo")
	} else {
		seed, err := hex.DecodeString(*seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			log.Fatalf("witnessd: -seed must be %d hex bytes", ed25519.SeedSize)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	}

	w := witnesskit.NewWorker(priv, *relayURL)
	log.Printf("witnessd: witness key %s; polling %s every %s; filing intake on %s (the one write)",
		hex.EncodeToString(w.Key()), *relayURL, *interval, *intakeAddr)

	go func() {
		if err := http.ListenAndServe(*intakeAddr, w.IntakeHandler()); err != nil {
			log.Printf("witnessd: intake server exited: %v", err)
			os.Exit(1)
		}
	}()
	for {
		n, err := w.RunOnce()
		if err != nil {
			log.Printf("witnessd: poll: %v", err)
		} else if n > 0 {
			log.Printf("witnessd: countersigned %d log(s)", n)
		}
		time.Sleep(*interval)
	}
}
