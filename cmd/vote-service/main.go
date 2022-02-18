package main

import (
	"context"
	"fmt"
	"io"
	golog "log"
	"os"
	"os/signal"
	"strconv"

	"github.com/OpenSlides/openslides-vote-service/collect/run"
	"github.com/OpenSlides/openslides-vote-service/internal/log"
)

func main() {
	ctx, cancel := interruptContext()
	defer cancel()

	log.SetInfoLogger(golog.Default())
	if dev, _ := strconv.ParseBool(os.Getenv("OPENSLIDES_DEVELOPMENT")); dev {
		log.SetDebugLogger(golog.New(os.Stderr, "DEBUG ", golog.LstdFlags))
	}

	if err := run.Run(ctx, os.Environ(), secret); err != nil {
		log.Info("Error: %v", err)
	}
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

func secret(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", fmt.Errorf("open secret file %s: %w", file, err)
	}

	secret, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("reading %q: %w", file, err)
	}

	return string(secret), nil
}
