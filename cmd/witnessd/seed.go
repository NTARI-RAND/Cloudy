package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

// witnessKey never includes input bytes or paths in diagnostics.
func witnessKey(seedHex, seedPath string) (ed25519.PrivateKey, error) {
	if seedHex != "" && seedPath != "" {
		return nil, errors.New("-seed and -seed-file are mutually exclusive")
	}
	if seedPath != "" {
		var err error
		seedHex, err = readSeedHex(seedPath)
		if err != nil {
			return nil, err
		}
	}

	if seedHex == "" && seedPath == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("seed must contain exactly 64 hex digits")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func readSeedHex(path string) (string, error) {
	file, err := openSeedFile(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, 67))
	if err != nil {
		return "", errors.New("cannot read -seed-file")
	}
	if len(data) > 66 {
		return "", errors.New("-seed-file must contain 64 hex digits with optional newline")
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"), nil
}
