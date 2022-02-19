package main

import (
	"crypto/rand"
	"encoding/base64"
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
		return fmt.Errorf("Usage: %s BASE64_KEY", os.Args[0])
	}

	key, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil {
		return fmt.Errorf("decoding key: %w", err)
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
