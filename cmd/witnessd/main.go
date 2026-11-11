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
	seedHex := flag.String("seed", "", "DEPRECATED: hex ed25519 seed; use -seed-file to keep secrets out of process arguments")
	seedFile := flag.String("seed-file", "", "protected file containing 64 hex seed digits; Linux/macOS owner-only permissions required")
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "seed-file" && f.Value.String() == "" {
			log.Fatal("witnessd: -seed-file must not be empty")
		}
	})

	priv, err := witnessKey(*seedHex, *seedFile)
	if err != nil {
		log.Fatalf("witnessd: %v", err)
	}
	if *seedHex != "" {
		log.Print("witnessd: -seed is deprecated; migrate to -seed-file to avoid process-argument and shell-history exposure")
	}
	if *seedHex == "" && *seedFile == "" {
		log.Print("witnessd: EPHEMERAL key (amnesia on restart is total); use -seed-file for a persistent identity beyond a demo")
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
