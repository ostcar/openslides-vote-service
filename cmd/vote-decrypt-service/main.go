package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/OpenSlides/openslides-vote-service/backends/memory"
	"github.com/OpenSlides/openslides-vote-service/decrypt"
	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
	"github.com/OpenSlides/openslides-vote-service/decrypt/grpc"
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

	mainKey, _, err := ed25519.GenerateKey(random)
	if err != nil {
		return fmt.Errorf("creating main key: %w", err)
	}

	cr := crypto.New(mainKey, random)

	decrypter := decrypt.New(cr, memory.New())

	if err := grpc.RunServer(ctx, decrypter, "localhost:9014"); err != nil {
		return fmt.Errorf("running grpc server: %w", err)
	}

	return nil
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
