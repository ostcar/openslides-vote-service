package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/OpenSlides/openslides-vote-service/decrypt"
	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
	"github.com/OpenSlides/openslides-vote-service/decrypt/grpc"
	"github.com/OpenSlides/openslides-vote-service/decrypt/store"
)

func main() {
	ctx, cancel := interruptContext()
	defer cancel()

	if err := run(ctx); err != nil {
		log.Printf("Error: %v", err)
	}
}

func run(ctx context.Context) error {
	random := rand.Reader

	if len(os.Args) < 2 {
		return fmt.Errorf("Usage: %s main_key_file", os.Args[0])
	}

	// TODO: set port and vote_data path via flags or environment

	mainKey, err := readMainKey(os.Args[1])
	if err != nil {
		return fmt.Errorf("getting main key: %w", err)
	}

	cr := crypto.New(mainKey, random)

	st := store.New("vote_data")

	decrypter := decrypt.New(cr, st)

	if err := grpc.RunServer(ctx, decrypter, ":9014"); err != nil {
		return fmt.Errorf("running grpc server: %w", err)
	}

	return nil
}

// readMainKey reads the first 32 bytes from the given file. It returns an
// error, if the file is shorter.
func readMainKey(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open main file: %w", err)
	}
	defer f.Close()

	key := make([]byte, 32)
	if _, err := io.ReadFull(f, key); err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}

	return key, nil
}

// interruptContext works like signal.NotifyContext
//
// In only listens on os.Interrupt. If the signal is received two times,
// os.Exit(1) is called.
func interruptContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		cancel()

		// If the signal was send for the second time, make a hard cut.
		<-sigint
		os.Exit(1)
	}()
	return ctx, cancel
}
