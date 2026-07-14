// Command cloudy-enroll drives this frontend through the SoHoLINK coordinator's
// operator onboarding lifecycle (apply → register the 7-key set → email
// verification → conformance A/B → active) and reports whether the operator
// became active.
//
// The coordinator emails a 6-digit verification code during the run and never
// returns it in an API response, so the code is supplied out-of-band: either
// interactively (default — prompts on stdin once the code has been sent) or by
// polling a file (-code-file), which suits automated/containerized bring-up.
//
// Point -portal at the coordinator's PORTAL surface (e.g. http://portal:8080 on
// the coordinator's own network). The public edge gates /operators/apply behind
// the federation disclaimer, so enrollment is a trusted, pre-launch bring-up
// step, not a public-internet flow.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/NTARI-RAND/Cloudy/internal/enroll"
	"github.com/NTARI-RAND/Cloudy/internal/opcred"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "cloudy-enroll:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, in io.Reader) error {
	fs := flag.NewFlagSet("cloudy-enroll", flag.ContinueOnError)
	fs.SetOutput(out)
	portal := fs.String("portal", "", "coordinator portal base URL (e.g. http://portal:8080)")
	slug := fs.String("slug", "", "operator id (^[a-z0-9-]{1,64}$)")
	name := fs.String("name", "", "operator display name")
	email := fs.String("email", "", "operator contact email (receives the verification code)")
	phone := fs.String("phone", "", "operator contact phone (optional)")
	keysDir := fs.String("keys", "", "directory holding (or, with -gen-keys, receiving) the 7 key-seed files")
	genKeys := fs.Bool("gen-keys", false, "generate a fresh keyset into -keys (fails if one already exists)")
	session := fs.String("session", "", "verification session id (default: derived from -slug)")
	codeFile := fs.String("code-file", "", "poll this file for the verification code instead of prompting on stdin")
	codeWait := fs.Duration("code-wait", 5*time.Minute, "how long to wait for the verification code")
	if err := fs.Parse(args); err != nil {
		return err
	}

	for _, req := range []struct{ v, n string }{
		{*portal, "portal"}, {*slug, "slug"}, {*name, "name"}, {*email, "email"}, {*keysDir, "keys"},
	} {
		if req.v == "" {
			return fmt.Errorf("-%s is required", req.n)
		}
	}
	sess := *session
	if sess == "" {
		sess = "enroll-" + *slug
	}

	ks, err := loadOrGenKeyset(*keysDir, *genKeys, out)
	if err != nil {
		return err
	}

	codeSrc := stdinCodeSource(out, in)
	if *codeFile != "" {
		codeSrc = fileCodeSource(*codeFile, *codeWait, out)
	}

	c := enroll.NewClient(*portal)
	fmt.Fprintf(out, "enrolling %q at %s ...\n", *slug, *portal)
	res, err := c.Enroll(context.Background(), enroll.Config{
		Slug: *slug, Name: *name, Email: *email, Phone: *phone,
		SessionID: sess, Keyset: ks, Code: codeSrc,
	})
	if res != nil {
		fmt.Fprintf(out, "keys_registered=%d verified=%v conformance_passed=%v activated=%v run_id=%s\n",
			res.KeysRegistered, res.Verified, res.ConformancePassed, res.Activated, res.RunID)
	}
	if err != nil {
		return err
	}
	if res.Activated {
		fmt.Fprintf(out, "OPERATOR ACTIVE: %s\n", res.OperatorID)
		return nil
	}
	fmt.Fprintln(out, "enrollment completed but operator is not yet active")
	return nil
}

func loadOrGenKeyset(dir string, gen bool, out io.Writer) (*opcred.Keyset, error) {
	if gen {
		ks, err := opcred.GenerateKeyset()
		if err != nil {
			return nil, fmt.Errorf("generate keyset: %w", err)
		}
		if err := ks.Save(dir); err != nil {
			return nil, fmt.Errorf("save keyset to %s: %w", dir, err)
		}
		fmt.Fprintf(out, "generated a fresh 7-key set in %s\n", dir)
		return ks, nil
	}
	ks, err := opcred.LoadKeyset(dir)
	if err != nil {
		return nil, fmt.Errorf("load keyset from %s: %w (use -gen-keys to create one)", dir, err)
	}
	return ks, nil
}

func stdinCodeSource(out io.Writer, in io.Reader) enroll.CodeSource {
	return enroll.CodeSourceFunc(func(ctx context.Context) (string, error) {
		fmt.Fprint(out, "enter the emailed verification code: ")
		s := bufio.NewScanner(in)
		if !s.Scan() {
			if err := s.Err(); err != nil {
				return "", err
			}
			return "", errors.New("no verification code provided on stdin")
		}
		return strings.TrimSpace(s.Text()), nil
	})
}

func fileCodeSource(path string, wait time.Duration, out io.Writer) enroll.CodeSource {
	return enroll.CodeSourceFunc(func(ctx context.Context) (string, error) {
		fmt.Fprintf(out, "waiting up to %s for the verification code in %s ...\n", wait, path)
		ctx, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			if b, err := os.ReadFile(path); err == nil {
				if code := strings.TrimSpace(string(b)); code != "" {
					return code, nil
				}
			}
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("timed out waiting for the verification code in %s", path)
			case <-t.C:
			}
		}
	})
}
