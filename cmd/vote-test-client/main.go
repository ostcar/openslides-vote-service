package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
)

func main() {
	if err := run(); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("Usage: %s POLL_KEY_FILE", os.Args[0])
	}

	key, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("reading poll key file: %w", err)
	}

	civer, err := crypto.Encrypt(rand.Reader, key, []byte(`"Y"`))
	if err != nil {
		return fmt.Errorf("encrypting vote: %w", err)
	}
	vote := struct {
		Value []byte `json:"value"`
	}{
		civer,
	}

	encoded, err := json.Marshal(vote)
	if err != nil {
		return fmt.Errorf("marshal vote: %w", err)
	}

	fmt.Println(string(encoded))
	return nil
}
