package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/OpenSlides/vote-decrypt/crypto"
)

func main() {
	if err := run(); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("Usage: %s base64(POLL_KEY) vote", os.Args[0])
	}

	pubKey, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil {
		return fmt.Errorf("decoding poll key: %w", err)
	}

	rawVote := []byte(os.Args[2])

	cipher, err := crypto.Encrypt(rand.Reader, pubKey, rawVote)
	if err != nil {
		return fmt.Errorf("encrypting vote: %w", err)
	}
	log.Println(cipher)

	vote := struct {
		Value []byte `json:"value"`
	}{
		cipher,
	}
	encoded, err := json.Marshal(vote)
	if err != nil {
		return fmt.Errorf("marshal vote: %w", err)
	}

	fmt.Println(string(encoded))
	return nil
}
