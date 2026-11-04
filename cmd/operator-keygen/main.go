// Command operator-keygen bootstraps an operator credential: it generates the
// seven-key Ed25519 keyset into a directory and prints the seven public keys
// (base64, index order — paste-ready for key registration) plus the keyset
// hash. With -root it also bootstraps the file-backed root-of-trust seed.
//
// It NEVER prints private material and refuses to overwrite any existing seed
// file.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/NTARI-RAND/Cloudy/internal/opcred"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "operator-keygen:", err)
		os.Exit(1)
	}
}

// run is the testable body of the command. It writes only public material to
// stdout.
func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("operator-keygen", flag.ContinueOnError)
	fs.SetOutput(stdout)
	dir := fs.String("dir", "", "directory to write the seven keyset seed files into (required)")
	rootPath := fs.String("root", "", "optional path to also bootstrap the file-backed root-of-trust seed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir is required")
	}
	return bootstrap(*dir, *rootPath, stdout)
}

func bootstrap(dir, rootPath string, stdout io.Writer) error {
	ks, err := opcred.GenerateKeyset()
	if err != nil {
		return err
	}
	if err := ks.Save(dir); err != nil {
		// Save refuses to overwrite and names the colliding file.
		return err
	}

	var output bytes.Buffer
	fmt.Fprintf(&output, "keyset written to %s\n", dir)
	fmt.Fprintln(&output, "public keys (base64, index order):")
	for i, pub := range ks.PublicKeys() {
		fmt.Fprintf(&output, "  %d: %s\n", i, base64.StdEncoding.EncodeToString(pub))
	}
	hash := ks.Hash()
	fmt.Fprintf(&output, "keyset hash: %s\n", base64.StdEncoding.EncodeToString(hash[:]))

	if rootPath != "" {
		root, err := opcred.GenerateFileRoot(rootPath)
		if err != nil {
			return err
		}
		fmt.Fprintf(&output, "root seed written to %s (software stand-in for a device root)\n", rootPath)
		fmt.Fprintf(&output, "root public key: %s\n", base64.StdEncoding.EncodeToString(root.PublicKey()))
	}
	_, err = io.Copy(stdout, &output)
	return err
}
